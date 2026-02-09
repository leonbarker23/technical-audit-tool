import os
import sys
import json
import re
import subprocess
import tempfile
import webbrowser
import threading
import ipaddress
import socket
import shutil

import ollama
from flask import Flask, Response, request, stream_with_context, render_template, send_from_directory
from scan import MSPConsultantTool, classify_target, _get_local_interfaces, is_admin, _find_nmap, ensure_dependencies

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) or os.getcwd()

app = Flask(__name__)

# Only allow characters that are valid in an IP, CIDR, or hostname.
# Rejects anything that could be interpreted as nmap flags or shell metacharacters.
_TARGET_RE = re.compile(r'^[A-Za-z0-9.\-/:]+$')

# Client name: letters, digits, spaces, hyphens, underscores.  Becomes a folder name.
_CLIENT_RE = re.compile(r'^[A-Za-z0-9 _-]+$')

# Track active processes by session ID for stop functionality
_active_processes = {}

# Regex to strip ANSI escape codes from PowerShell output
_ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def _find_powershell7():
    """Find PowerShell 7 executable on Windows."""
    # Check for pwsh in PATH
    pwsh_path = shutil.which("pwsh")
    if pwsh_path:
        return pwsh_path
    # Check common install locations
    for path in [
        r'C:\Program Files\PowerShell\7\pwsh.exe',
        os.path.expandvars(r'%ProgramFiles%\PowerShell\7\pwsh.exe'),
    ]:
        if os.path.exists(path):
            return path
    return None


def _validate_target(target: str) -> bool:
    """Return True only if target looks like a plain IP, CIDR, or hostname."""
    if not _TARGET_RE.match(target):
        return False
    # Must resolve to at least one of: bare IP, CIDR network, or resolvable hostname
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False


def sse(data, event=None):
    """Format a Server-Sent Event."""
    msg = f"event: {event}\n" if event else ""
    for line in str(data).split("\n"):
        msg += f"data: {line}\n"
    return msg + "\n"


# ── routes ──────────────────────────────────────────

@app.route("/")
def index():
    interfaces = _get_local_interfaces()
    return render_template("index.html", interfaces=interfaces)


@app.route("/scan")
def scan():
    target = request.args.get("target", "").strip()
    client = request.args.get("client", "").strip()
    session_id = request.args.get("session", "").strip()

    if not client or not _CLIENT_RE.match(client):
        return Response(sse("Invalid or missing client name.", event="scan_error"),
                        mimetype="text/event-stream")

    if not target:
        return Response(sse("No target provided.", event="scan_error"),
                        mimetype="text/event-stream")

    if not _validate_target(target):
        return Response(sse("Invalid target. Enter a valid IP, CIDR, or hostname.", event="scan_error"),
                        mimetype="text/event-stream")

    scan_depth = request.args.get("depth", "deep").strip().lower()
    if scan_depth not in ("deep", "medium", "fast"):
        return Response(sse("Invalid scan depth.", event="scan_error"),
                        mimetype="text/event-stream")

    scan_type = classify_target(target)          # single | subnet — drives LLM prompt choice
    if scan_type is None:
        return Response(sse(f"'{target}' could not be resolved.", event="scan_error"),
                        mimetype="text/event-stream")

    def generate():
        tool  = MSPConsultantTool()
        args  = tool.SCAN_PROFILES[scan_depth]
        label = scan_depth.capitalize() + " Scan"

        yield sse(f"[*] Target  : {target}")
        yield sse(f"[*] Scan    : {label}")
        yield sse(f"[*] Flags   : {args}")
        yield sse("")

        # ── nmap ─────────────────────────────────────
        xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="nmap_")
        os.close(xml_fd)
        nmap_exe = _find_nmap() or 'nmap'
        cmd  = [nmap_exe] + args.split() + ["-v", "-oX", xml_path, target]
        proc = None

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)

            # Register process for stop functionality
            if session_id:
                _active_processes[session_id] = proc

            for line in proc.stdout:
                stripped = line.rstrip("\n")
                if stripped:
                    yield sse(stripped)
            proc.wait()

            if proc.returncode != 0:
                yield sse(f"[!] nmap exited with code {proc.returncode}", event="scan_error")
                return

            # ── parse ──────────────────────────────────
            yield sse("Parsing scan results…", event="status")
            tech_data = tool._parse_nmap_xml(xml_path)
            if not tech_data:
                yield sse("No hosts found in scan results.", event="scan_error")
                return

            # ── LLM (streamed token-by-token) ────────────
            yield sse("Generating vulnerability report…", event="status")
            active_data = {ip: info for ip, info in tech_data.items() if info.get("status") == "up"}
            summary = tool._build_summary(active_data)
            prompt  = (tool._prompt_single(summary)
                       if scan_type == "single"
                       else tool._prompt_subnet(summary, len(active_data)))

            report_text = ""
            try:
                for chunk in ollama.generate(model=tool.model,
                                             prompt=prompt,
                                             stream=True):
                    tok = chunk.get("response", "")
                    if tok:
                        report_text += tok
                        yield sse(tok, event="report_chunk")
            except Exception as exc:
                yield sse(f"Ollama error: {exc}\n"
                          f"Ensure ollama is running and '{tool.model}' is pulled.",
                          event="scan_error")

            # ── save to disk ─────────────────────────────
            json_file, md_file = tool.save_outputs(tech_data, report_text or None, scan_type, client, target)

            # ── notify browser of generated files ────────
            yield sse(json.dumps({
                "json": f"{client}/{json_file}",
                "md":   f"{client}/{md_file}",
            }), event="files")
            yield sse("Scan and analysis complete.", event="done")

        finally:
            # Clean up process tracking
            if session_id and session_id in _active_processes:
                del _active_processes[session_id]
            if proc and proc.poll() is None:
                proc.kill()
            if os.path.exists(xml_path):
                os.unlink(xml_path)

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream", headers=headers)


@app.route("/download/<path:filename>")
def download(filename):
    """Serve generated reports.  send_from_directory prevents path-traversal."""
    return send_from_directory(BASE_DIR, filename)


@app.route("/stop", methods=["POST"])
def stop_process():
    """Stop a running scan or assessment by session ID."""
    session_id = request.args.get("session", "").strip()
    if not session_id:
        return {"error": "No session ID provided"}, 400

    proc = _active_processes.pop(session_id, None)
    if proc and proc.poll() is None:
        try:
            proc.kill()
            return {"status": "stopped", "session": session_id}
        except Exception as e:
            return {"error": str(e)}, 500

    return {"status": "not_found", "session": session_id}


# ── Zero Trust Assessment ────────────────────────────────────────────────────

@app.route("/zerotrust")
def zerotrust():
    client = request.args.get("client", "").strip()
    session_id = request.args.get("session", "").strip()

    if not client or not _CLIENT_RE.match(client):
        return Response(sse("Invalid or missing client name.", event="zt_error"),
                        mimetype="text/event-stream")

    def generate():
        from datetime import datetime

        # Check for PowerShell 7
        pwsh_path = _find_powershell7()
        if not pwsh_path:
            yield sse("PowerShell 7 (pwsh) not found.", event="zt_error")
            yield sse("Install with: winget install Microsoft.PowerShell", event="zt_error")
            return

        yield sse("[*] PowerShell 7 found: " + pwsh_path)
        yield sse("[*] Client: " + client)
        yield sse("")

        # Create client folder if needed
        client_folder = os.path.join(BASE_DIR, client)
        os.makedirs(client_folder, exist_ok=True)

        # Run the Zero Trust assessment PowerShell script
        script_path = os.path.join(BASE_DIR, "zerotrust.ps1")
        if not os.path.exists(script_path):
            yield sse("zerotrust.ps1 script not found.", event="zt_error")
            return

        yield sse("[*] Running Zero Trust Assessment...")
        yield sse("[*] A browser window will open for Microsoft authentication")
        yield sse("")

        cmd = [
            pwsh_path, "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", script_path,
            "-OutputPath", BASE_DIR,
            "-ClientName", client
        ]

        proc = None
        json_file = None
        zt_json_file = None
        html_file = None

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=BASE_DIR,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Register process for stop functionality
            if session_id:
                _active_processes[session_id] = proc

            in_output_block = False
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                # Strip ANSI codes
                stripped = _ANSI_ESCAPE.sub('', stripped)

                # Parse output file markers
                if stripped == "=== OUTPUT_FILES ===":
                    in_output_block = True
                    continue
                elif stripped == "=== END_OUTPUT_FILES ===":
                    in_output_block = False
                    continue
                elif in_output_block:
                    if stripped.startswith("JSON:"):
                        json_file = stripped[5:]
                    elif stripped.startswith("ZTJSON:"):
                        zt_json_file = stripped[7:]
                    elif stripped.startswith("HTML:"):
                        html_file = stripped[5:]
                    continue

                if stripped:
                    yield sse(stripped)

            proc.wait()

            if proc.returncode != 0:
                yield sse(f"[!] Assessment exited with code {proc.returncode}", event="zt_error")
                return

            # Check if we got a JSON file
            if not json_file:
                # Look for most recent JSON in client folder
                import glob
                json_files = glob.glob(os.path.join(client_folder, "zerotrust_*.json"))
                if json_files:
                    json_file = os.path.basename(max(json_files, key=os.path.getctime))
                    json_file = f"{client}/{json_file}"

            if not json_file or not os.path.exists(os.path.join(BASE_DIR, json_file)):
                yield sse("[!] No assessment data file found.", event="zt_error")
                return

            # Load the assessment data
            yield sse("Parsing assessment data...", event="status")
            with open(os.path.join(BASE_DIR, json_file), "r") as f:
                assessment_data = json.load(f)

            # Load detailed ZT assessment data if available (from Microsoft module)
            zt_assessment_data = None
            if zt_json_file and os.path.exists(os.path.join(BASE_DIR, zt_json_file)):
                yield sse("Loading detailed Microsoft assessment data...", event="status")
                try:
                    with open(os.path.join(BASE_DIR, zt_json_file), "r", encoding="utf-8-sig") as f:
                        zt_assessment_data = json.load(f)
                except Exception as e:
                    yield sse(f"[!] Could not load detailed data: {e}")

            # Generate AI analysis
            yield sse("Generating Zero Trust analysis report...", event="status")

            prompt = _zerotrust_prompt(assessment_data, zt_assessment_data)
            report_text = ""

            try:
                for chunk in ollama.generate(model="qwen2.5:7b",
                                             prompt=prompt,
                                             stream=True):
                    tok = chunk.get("response", "")
                    if tok:
                        report_text += tok
                        yield sse(tok, event="report_chunk")
            except Exception as exc:
                yield sse(f"Ollama error: {exc}", event="zt_error")
                yield sse("Ensure ollama is running and 'qwen2.5:7b' model is available.", event="zt_error")
                return

            # Save the markdown report
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
            md_file = f"zerotrust_report_{timestamp}.md"
            md_path = os.path.join(client_folder, md_file)
            with open(md_path, "w") as f:
                f.write(report_text)

            # Notify browser of files
            files_data = {
                "json": json_file,
                "md": f"{client}/{md_file}",
            }
            if html_file:
                files_data["html"] = html_file

            yield sse(json.dumps(files_data), event="files")
            yield sse("Zero Trust Assessment complete.", event="done")

        except Exception as exc:
            yield sse(f"[!] Error: {exc}", event="zt_error")
        finally:
            # Clean up process tracking
            if session_id and session_id in _active_processes:
                del _active_processes[session_id]
            if proc and proc.poll() is None:
                proc.kill()

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream", headers=headers)


# ── Azure Resource Inventory ──────────────────────────────────────────────────

@app.route("/azureinventory")
def azureinventory():
    client = request.args.get("client", "").strip()
    session_id = request.args.get("session", "").strip()
    include_security = request.args.get("securityCenter", "").lower() == "true"
    skip_diagram = request.args.get("skipDiagram", "").lower() == "true"

    if not client or not _CLIENT_RE.match(client):
        return Response(sse("Invalid or missing client name.", event="ari_error"),
                        mimetype="text/event-stream")

    def generate():
        from datetime import datetime

        # Check for PowerShell 7
        pwsh_path = _find_powershell7()
        if not pwsh_path:
            yield sse("PowerShell 7 (pwsh) not found.", event="ari_error")
            yield sse("Install with: winget install Microsoft.PowerShell", event="ari_error")
            return

        yield sse("[*] PowerShell 7 found: " + pwsh_path)
        yield sse("[*] Client: " + client)
        yield sse("")

        # Create client folder if needed
        client_folder = os.path.join(BASE_DIR, client)
        os.makedirs(client_folder, exist_ok=True)

        # Run the Azure Resource Inventory PowerShell script
        script_path = os.path.join(BASE_DIR, "azureinventory.ps1")
        if not os.path.exists(script_path):
            yield sse("azureinventory.ps1 script not found.", event="ari_error")
            return

        yield sse("[*] Running Azure Resource Inventory...")
        yield sse("[*] A browser window will open for Azure authentication")
        yield sse("")

        cmd = [
            pwsh_path, "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", script_path,
            "-OutputPath", BASE_DIR,
            "-ClientName", client
        ]

        if include_security:
            cmd.append("-IncludeSecurityCenter")
        if skip_diagram:
            cmd.append("-SkipDiagram")

        proc = None
        json_file = None
        excel_file = None
        diagram_file = None

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=BASE_DIR,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Register process for stop functionality
            if session_id:
                _active_processes[session_id] = proc

            in_output_block = False
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                # Remove ANSI color codes
                stripped = _ANSI_ESCAPE.sub('', stripped)

                # Parse output file markers
                if stripped == "=== OUTPUT_FILES ===":
                    in_output_block = True
                    continue
                elif stripped == "=== END_OUTPUT_FILES ===":
                    in_output_block = False
                    continue
                elif in_output_block:
                    if stripped.startswith("JSON:"):
                        json_file = stripped[5:]
                    elif stripped.startswith("EXCEL:"):
                        excel_file = stripped[6:]
                    elif stripped.startswith("DIAGRAM:"):
                        diagram_file = stripped[8:]
                    continue

                if stripped:
                    yield sse(stripped)

            proc.wait()

            if proc.returncode != 0:
                yield sse(f"[!] Inventory exited with code {proc.returncode}", event="ari_error")
                return

            # Check if we got a JSON file
            if not json_file:
                # Look for most recent JSON in client folder
                import glob
                ari_folder = os.path.join(client_folder, "AzureInventory")
                json_files = glob.glob(os.path.join(ari_folder, "azureinventory_*.json"))
                if json_files:
                    json_file = os.path.basename(max(json_files, key=os.path.getctime))
                    json_file = f"{client}/AzureInventory/{json_file}"

            if not json_file or not os.path.exists(os.path.join(BASE_DIR, json_file)):
                yield sse("[!] No inventory data file found.", event="ari_error")
                return

            # Load the inventory data
            yield sse("Parsing inventory data...", event="status")
            with open(os.path.join(BASE_DIR, json_file), "r") as f:
                inventory_data = json.load(f)

            # Generate AI analysis
            yield sse("Generating Azure infrastructure analysis report...", event="status")

            prompt = _azureinventory_prompt(inventory_data)
            report_text = ""

            try:
                for chunk in ollama.generate(model="qwen2.5:7b",
                                             prompt=prompt,
                                             stream=True):
                    tok = chunk.get("response", "")
                    if tok:
                        report_text += tok
                        yield sse(tok, event="report_chunk")
            except Exception as exc:
                yield sse(f"Ollama error: {exc}", event="ari_error")
                yield sse("Ensure ollama is running and 'qwen2.5:7b' model is available.", event="ari_error")
                return

            # Save the markdown report
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
            md_file = f"azureinventory_report_{timestamp}.md"
            ari_folder = os.path.join(client_folder, "AzureInventory")
            md_path = os.path.join(ari_folder, md_file)
            with open(md_path, "w") as f:
                f.write(report_text)

            # Notify browser of files
            files_data = {
                "json": json_file,
                "md": f"{client}/AzureInventory/{md_file}",
            }
            if excel_file:
                files_data["excel"] = excel_file
            if diagram_file:
                files_data["diagram"] = diagram_file

            yield sse(json.dumps(files_data), event="files")
            yield sse("Azure Resource Inventory complete.", event="done")

        except Exception as exc:
            yield sse(f"[!] Error: {exc}", event="ari_error")
        finally:
            # Clean up process tracking
            if session_id and session_id in _active_processes:
                del _active_processes[session_id]
            if proc and proc.poll() is None:
                proc.kill()

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream", headers=headers)


def _azureinventory_prompt(data: dict) -> str:
    """Build the LLM prompt for Azure Resource Inventory analysis."""
    metadata = data.get("metadata", {})
    summary = data.get("summary", {})
    subscriptions = data.get("subscriptions", [])
    compute = data.get("compute", {})
    networking = data.get("networking", {})
    storage = data.get("storage", {})
    databases = data.get("databases", {})
    security = data.get("security", {})

    # Build resource type summary
    resource_types = summary.get("resourcesByType", {})
    type_summary = "\n".join([f"- {k}: {v}" for k, v in sorted(resource_types.items(), key=lambda x: -x[1]) if v > 0][:15])

    # Build location summary
    locations = summary.get("resourcesByLocation", {})
    location_summary = "\n".join([f"- {k}: {v}" for k, v in sorted(locations.items(), key=lambda x: -x[1]) if v > 0])

    # Build subscription summary
    sub_summary = "\n".join([f"- {s.get('name', 'Unknown')} ({s.get('state', 'Unknown')})" for s in subscriptions[:10]])

    # Build compute summary
    vms = compute.get("virtualMachines", [])
    vm_summary = ""
    if vms:
        vm_by_size = {}
        vm_by_state = {"running": 0, "stopped": 0, "other": 0}
        for vm in vms:
            size = vm.get("vmSize", "Unknown")
            vm_by_size[size] = vm_by_size.get(size, 0) + 1
            state = (vm.get("powerState") or "").lower()
            if "running" in state:
                vm_by_state["running"] += 1
            elif "stopped" in state or "deallocated" in state:
                vm_by_state["stopped"] += 1
            else:
                vm_by_state["other"] += 1
        vm_summary = f"""
Virtual Machines: {len(vms)} total
- Running: {vm_by_state['running']}
- Stopped/Deallocated: {vm_by_state['stopped']}
- Top VM sizes: {', '.join([f"{k}({v})" for k, v in sorted(vm_by_size.items(), key=lambda x: -x[1])[:5]])}
"""

    # Build networking summary
    vnets = networking.get("virtualNetworks", [])
    nsgs = networking.get("networkSecurityGroups", [])
    lbs = networking.get("loadBalancers", [])
    pips = networking.get("publicIPs", [])
    net_summary = f"""
- Virtual Networks: {len(vnets)}
- Network Security Groups: {len(nsgs)}
- Load Balancers: {len(lbs)}
- Public IPs: {len(pips)}
"""

    # Build storage summary
    storage_accounts = storage.get("storageAccounts", [])
    storage_summary = f"- Storage Accounts: {len(storage_accounts)}"

    # Build database summary
    sql_servers = databases.get("sqlServers", [])
    sql_dbs = databases.get("sqlDatabases", [])
    cosmos = databases.get("cosmosDbAccounts", [])
    db_summary = f"""
- SQL Servers: {len(sql_servers)}
- SQL Databases: {len(sql_dbs)}
- Cosmos DB Accounts: {len(cosmos)}
"""

    # Build security summary
    key_vaults = security.get("keyVaults", [])
    recommendations = security.get("recommendations", [])
    sec_summary = f"""
- Key Vaults: {len(key_vaults)}
- Security Recommendations: {len(recommendations)}
"""

    # Security recommendations detail
    sec_recommendations = ""
    if recommendations:
        sec_recommendations = "\n### Security Recommendations\n"
        for rec in recommendations[:20]:
            severity = rec.get("severity", "Unknown")
            recommendation = rec.get("recommendation", "Unknown")
            sec_recommendations += f"- **[{severity}]** {recommendation}\n"

    return f"""You are an Azure infrastructure consultant performing an Azure Resource Inventory analysis for an MSP client.

Analyse the following Azure environment data and provide a structured infrastructure assessment report.

## Tenant Information
- Client: {metadata.get('clientName', 'Unknown')}
- Assessment Date: {metadata.get('assessmentDate', 'Unknown')}
- Tenant ID: {metadata.get('tenantId', 'Unknown')}

## Summary
- Total Resources: {summary.get('totalResources', 0)}
- Subscriptions: {summary.get('subscriptionCount', 0)}

## Subscriptions
{sub_summary}

## Resources by Type (Top 15)
{type_summary}

## Resources by Location
{location_summary}

## Compute Resources
{vm_summary}
- App Services: {len(compute.get('appServices', []))}
- Functions: {len(compute.get('functions', []))}
- AKS Clusters: {len(compute.get('aks', []))}
- VM Scale Sets: {len(compute.get('vmScaleSets', []))}

## Networking
{net_summary}

## Storage
{storage_summary}

## Databases
{db_summary}

## Security
{sec_summary}
{sec_recommendations}

---

CRITICAL FORMATTING RULES:
1. Use proper Markdown with # for main heading, ## for sections, ### for subsections
2. Add a BLANK LINE before and after every heading and bullet list
3. Do NOT repeat sections - each section should appear ONCE only
4. Reference SPECIFIC resource counts and types from the data above

Generate the report in this EXACT structure:

# Azure Resource Inventory Report

## Executive Summary

Write 2-3 paragraphs summarising the Azure environment, its scale, and key observations. Include total resource count and subscription count.

## Subscription Overview

List the subscriptions and their purpose (if inferable from names).

## Resource Inventory

### Compute Resources

Analyse VMs (sizes, states, distribution), App Services, Functions, and container resources.
- Note any over-provisioned or right-sizing opportunities
- Highlight stopped VMs that could be deallocated

### Networking

Analyse VNets, NSGs, load balancers, and public IPs.
- Comment on network architecture
- Note any security considerations

### Storage & Databases

Analyse storage accounts and database resources.
- Note storage tier usage
- Comment on database deployment patterns

## Architecture Observations

Comment on:
- Multi-region deployment (or lack thereof)
- Redundancy and availability
- Naming conventions
- Resource organisation

## Cost Optimisation Opportunities

Based on the inventory, suggest:
- Right-sizing opportunities (stopped VMs, underutilised resources)
- Reserved instance candidates
- Storage tier optimisation
- Orphaned resources

## Security Observations

Analyse key vaults and security recommendations (if available).
- Note any critical security gaps
- Recommend security improvements

## Recommendations Roadmap

### Immediate (0-30 days)

List 3-5 quick wins based on the inventory.

### Short-term (1-3 months)

List 3-5 important improvements.

### Medium-term (3-6 months)

List 2-3 strategic enhancements.

## Conclusion

Summarise key takeaways and next steps for the MSP engagement.

---

Be specific - reference actual resource counts and types. Use blank lines for readability."""


# ── M365 Assessment ───────────────────────────────────────────────────────────

@app.route("/m365assessment")
def m365assessment():
    client = request.args.get("client", "").strip()
    session_id = request.args.get("session", "").strip()
    skip_maester = request.args.get("skipMaester", "").lower() == "true"

    if not client or not _CLIENT_RE.match(client):
        return Response(sse("Invalid or missing client name.", event="m365_error"),
                        mimetype="text/event-stream")

    def generate():
        from datetime import datetime

        # Check for PowerShell 7
        pwsh_path = _find_powershell7()
        if not pwsh_path:
            yield sse("PowerShell 7 (pwsh) not found.", event="m365_error")
            yield sse("Install with: winget install Microsoft.PowerShell", event="m365_error")
            return

        yield sse("[*] PowerShell 7 found: " + pwsh_path)
        yield sse("[*] Client: " + client)
        yield sse("")

        # Create client folder if needed
        client_folder = os.path.join(BASE_DIR, client)
        os.makedirs(client_folder, exist_ok=True)

        # Run the M365 Assessment PowerShell script
        script_path = os.path.join(BASE_DIR, "m365assessment.ps1")
        if not os.path.exists(script_path):
            yield sse("m365assessment.ps1 script not found.", event="m365_error")
            return

        yield sse("[*] Running M365 Assessment...")
        yield sse("[*] A browser window will open for Microsoft authentication")
        yield sse("")

        cmd = [
            pwsh_path, "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", script_path,
            "-OutputPath", BASE_DIR,
            "-ClientName", client
        ]

        if skip_maester:
            cmd.append("-SkipMaester")

        proc = None
        json_file = None
        maester_html_file = None
        maester_json_file = None
        maester_md_file = None

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=BASE_DIR,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # Register process for stop functionality
            if session_id:
                _active_processes[session_id] = proc

            in_output_block = False
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                # Remove ANSI color codes
                stripped = _ANSI_ESCAPE.sub('', stripped)

                # Parse output file markers
                if stripped == "=== OUTPUT_FILES ===":
                    in_output_block = True
                    continue
                elif stripped == "=== END_OUTPUT_FILES ===":
                    in_output_block = False
                    continue
                elif in_output_block:
                    if stripped.startswith("JSON:"):
                        json_file = stripped[5:]
                    elif stripped.startswith("MAESTERHTML:"):
                        maester_html_file = stripped[12:]
                    elif stripped.startswith("MAESTERJSON:"):
                        maester_json_file = stripped[12:]
                    elif stripped.startswith("MAESTERMD:"):
                        maester_md_file = stripped[10:]
                    continue

                if stripped:
                    yield sse(stripped)

            proc.wait()

            if proc.returncode != 0:
                yield sse(f"[!] Assessment exited with code {proc.returncode}", event="m365_error")
                return

            # Check if we got a JSON file
            if not json_file:
                # Look for most recent JSON in client folder
                import glob
                json_files = glob.glob(os.path.join(client_folder, "m365assessment_*.json"))
                if json_files:
                    json_file = os.path.basename(max(json_files, key=os.path.getctime))
                    json_file = f"{client}/{json_file}"

            if not json_file or not os.path.exists(os.path.join(BASE_DIR, json_file)):
                yield sse("[!] No assessment data file found.", event="m365_error")
                return

            # Load the assessment data
            yield sse("Parsing assessment data...", event="status")
            with open(os.path.join(BASE_DIR, json_file), "r") as f:
                assessment_data = json.load(f)

            # Load Maester markdown report if available
            maester_md_content = None
            if maester_md_file and os.path.exists(os.path.join(BASE_DIR, maester_md_file)):
                try:
                    with open(os.path.join(BASE_DIR, maester_md_file), "r", encoding="utf-8", errors="replace") as f:
                        maester_md_content = f.read()
                    yield sse("Loaded Maester security report for analysis...", event="status")
                except Exception as e:
                    yield sse(f"[!] Could not read Maester report: {e}", event="status")

            # Generate AI analysis
            yield sse("Generating M365 analysis report...", event="status")

            prompt = _m365assessment_prompt(assessment_data, maester_md_content)
            report_text = ""

            try:
                for chunk in ollama.generate(model="qwen2.5:7b",
                                             prompt=prompt,
                                             stream=True):
                    tok = chunk.get("response", "")
                    if tok:
                        report_text += tok
                        yield sse(tok, event="report_chunk")
            except Exception as exc:
                yield sse(f"Ollama error: {exc}", event="m365_error")
                yield sse("Ensure ollama is running and 'qwen2.5:7b' model is available.", event="m365_error")
                return

            # Save the markdown report
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
            md_file = f"m365assessment_report_{timestamp}.md"
            md_path = os.path.join(client_folder, md_file)
            with open(md_path, "w") as f:
                f.write(report_text)

            # Notify browser of files
            files_data = {
                "json": json_file,
                "md": f"{client}/{md_file}",
            }
            if maester_html_file:
                files_data["maesterHtml"] = maester_html_file
            if maester_json_file:
                files_data["maesterJson"] = maester_json_file

            yield sse(json.dumps(files_data), event="files")
            yield sse("M365 Assessment complete.", event="done")

        except Exception as exc:
            yield sse(f"[!] Error: {exc}", event="m365_error")
        finally:
            # Clean up process tracking
            if session_id and session_id in _active_processes:
                del _active_processes[session_id]
            if proc and proc.poll() is None:
                proc.kill()

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream", headers=headers)


def _m365assessment_prompt(data: dict, maester_md_content: str = None) -> str:
    """Build the LLM prompt for M365 Assessment analysis."""
    metadata = data.get("metadata", {})
    licensing = data.get("licensing", {})
    security_score = data.get("securityScore", {})
    identity = data.get("identity", {})
    intune = data.get("intune", {})
    sharepoint = data.get("sharepoint", {})
    teams = data.get("teams", {})
    applications = data.get("applications", {})
    governance = data.get("governance", {})
    maester = data.get("maester", {})

    # Build license summary - filter out free/trial licenses that clutter the report
    skus = licensing.get("subscribedSkus", [])
    # Common free license SKUs that don't require analysis
    free_license_patterns = [
        "FREE", "FLOW_FREE", "POWER_BI_STANDARD", "POWER_AUTOMATE_FREE",
        "POWERAPPS_VIRAL", "TEAMS_EXPLORATORY", "RIGHTSMANAGEMENT_ADHOC",
        "WINDOWS_STORE", "STREAM", "MICROSOFT_BUSINESS_CENTER",
        "CCIBOTS_PRIVPREV_VIRAL", "FORMS_PRO", "PROJECT_MADEIRA_PREVIEW_IW",
        "CDS_O365_P1", "CDS_O365_P2", "CDS_O365_P3", "PBI_AZURE_UNAVAILABLE"
    ]
    paid_skus = [s for s in skus if not any(
        pattern in (s.get('skuPartNumber', '') or '').upper()
        for pattern in free_license_patterns
    )]
    license_summary = ""
    if paid_skus:
        license_summary = "\n".join([
            f"- {s.get('skuPartNumber', 'Unknown')}: {s.get('consumedUnits', 0)} / {s.get('prepaidUnits', 0)} assigned"
            for s in paid_skus[:15]
        ])

    # Build CA policy summary
    ca_policies = identity.get("conditionalAccess", [])
    enabled_policies = [p for p in ca_policies if p.get("state") == "enabled"]
    ca_summary = f"Total: {len(ca_policies)}, Enabled: {len(enabled_policies)}"

    # Build admin roles summary
    admin_roles = governance.get("adminRoles", [])
    roles_summary = "\n".join([
        f"- {r.get('roleName', 'Unknown')}: {r.get('memberCount', 0)} members"
        for r in sorted(admin_roles, key=lambda x: -x.get('memberCount', 0))[:10]
    ])

    # Build Maester summary
    maester_summary = ""
    maester_findings = ""
    if maester.get("summary") and not maester.get("summary", {}).get("error"):
        m = maester.get("summary", {})
        maester_summary = f"""
### Maester Security Test Results
- **Passed**: {m.get('passed', 0)}
- **Failed**: {m.get('failed', 0)}
- **Skipped**: {m.get('skipped', 0)}
- **Pass Rate**: {m.get('passRate', 0)}%
"""
        # Add failed test details
        failed_tests = maester.get("testResults", [])
        if failed_tests:
            maester_findings = "\n### Failed Security Tests\n"
            for test in failed_tests[:20]:
                name = test.get("name", "Unknown")
                block = test.get("block", "")
                maester_findings += f"- **{name}**"
                if block:
                    maester_findings += f" ({block})"
                maester_findings += "\n"

    # Build recommendations summary
    recommendations = security_score.get("recommendations", [])
    rec_summary = ""
    if recommendations:
        rec_summary = "\n### Top Security Score Recommendations\n"
        for r in recommendations[:10]:
            title = r.get("title", "Unknown")
            max_score = r.get("maxScore", 0)
            rec_summary += f"- **{title}** (+{max_score} points)\n"

    # Data gaps note
    data_gaps = metadata.get("dataGaps", [])
    gaps_note = ""
    if data_gaps:
        gaps_note = f"\n**Note:** Some data was not available: {', '.join(data_gaps)}\n"

    # Build Intune summary
    intune_devices = intune.get("managedDevices", {})
    intune_summary = ""
    if intune_devices.get("total", 0) > 0:
        intune_summary = f"""
- Managed Devices: {intune_devices.get('total', 0)}
- Compliant: {intune_devices.get('compliant', 0)} ({intune_devices.get('complianceRate', 0)}%)
- Non-Compliant: {intune_devices.get('nonCompliant', 0)}
- Compliance Policies: {len(intune.get('compliancePolicies', []))}
- Configuration Profiles: {len(intune.get('configurationProfiles', []))}
- App Protection Policies: {len(intune.get('appProtectionPolicies', []))}
"""

    # SharePoint storage
    sp_storage_gb = round(sharepoint.get("storageUsed", 0) / (1024**3), 2) if sharepoint.get("storageUsed") else 0

    return f"""You are a Microsoft 365 technical consultant performing a tenant assessment.

Analyse the following M365 tenant data and generate a structured assessment report.

=== RAW DATA FOR ANALYSIS ===

## Tenant Information
- Client: {metadata.get('clientName', 'Unknown')}
- Tenant: {metadata.get('tenantName', 'Unknown')}
- Primary Domain: {metadata.get('primaryDomain', 'Unknown')}
- Tenant Created: {metadata.get('createdDateTime', 'Unknown')}
- Assessment Date: {metadata.get('assessmentDate', 'Unknown')}
{gaps_note}

## User Summary
- Total Users: {licensing.get('totalUsers', 0)}
- Licensed Users: {licensing.get('licensedUsers', 0)}
- Guest Users: {licensing.get('guestUsers', 0)}

## License Inventory (Paid Licenses Only - free SKUs excluded)
{license_summary}

LICENSE SKU REFERENCE (use these EXACT mappings):
- SPE_E3 = Microsoft 365 E3
- SPE_E5 = Microsoft 365 E5
- SPE_A3 or M365EDU_A3 = Microsoft 365 A3 (Education)
- SPE_A5 or M365EDU_A5 = Microsoft 365 A5 (Education)
- ENTERPRISEPACK = Office 365 E3
- ENTERPRISEPREMIUM = Office 365 E5
- AAD_PREMIUM_P1 = Entra ID P1
- AAD_PREMIUM_P2 = Entra ID P2
- EMS = Enterprise Mobility + Security
- ATP_ENTERPRISE = Microsoft Defender for Office 365
- INTUNE_A = Microsoft Intune
Do NOT confuse A3/A5 (Education) with E3/E5 (Enterprise).

## MFA Status
- Registered: {identity.get('mfaStatus', {}).get('registered', 'N/A')} / {identity.get('mfaStatus', {}).get('total', 'N/A')} users
- Percentage: {identity.get('mfaStatus', {}).get('percentage', 'N/A')}%

## Conditional Access
- Total Policies: {len(ca_policies)}
- Enabled Policies: {len(enabled_policies)}

## Microsoft Secure Score
- Current Score: {security_score.get('currentScore', 0)} / {security_score.get('maxScore', 0)}
- Percentage: {security_score.get('percentage', 0)}%
- Identity Score: {security_score.get('identityScore', {}).get('percentage', 'N/A')}%
{rec_summary}

## Privileged Access
- Global Administrators: {identity.get('privilegedAccess', {}).get('globalAdminCount', 'N/A')}
- Active Directory Roles: {identity.get('privilegedAccess', {}).get('directoryRolesActive', 'N/A')}
- Named Locations: {len(governance.get('namedLocations', []))}
- Risky Users: {identity.get('riskyUsers', {}).get('atRisk', 0)}

### Admin Role Breakdown
{roles_summary}

## Device Management (Intune)
{intune_summary if intune_summary else "Intune data not available (license may be required)"}

## SharePoint & Teams
- SharePoint Sites: {sharepoint.get('siteCount', 0)}
- SharePoint Storage Used: {sp_storage_gb} GB
- Teams: {teams.get('teamsCount', 0)}

## Applications
- Enterprise Applications: {applications.get('enterpriseApps', 0)}
- App Registrations: {applications.get('appRegistrations', 0)}
{maester_summary}
{maester_findings}
{f'''
## Maester Security Test Results (Full Report)
This is the ACTUAL Maester security test output - use this to identify security gaps and themes.

{maester_md_content[:20000] if maester_md_content and len(maester_md_content) > 20000 else maester_md_content if maester_md_content else "Maester report not available."}
''' if maester_md_content else ''}

=== END RAW DATA ===

---

CRITICAL INSTRUCTIONS:
1. Use proper Markdown: # for main heading, ## for sections, ### for subsections
2. Add a BLANK LINE before and after every heading and bullet list
3. Do NOT repeat sections - each section appears ONCE only
4. Include SPECIFIC numbers from the data above
5. Use severity keywords: **Critical**, **High**, **Medium**, **Low**

Generate the report in this EXACT structure:

# Microsoft 365 Assessment Report

## Executive Summary

2-3 paragraphs providing a high-level overview of the tenant's security posture, key risks identified, and overall maturity level.

## 1. Licensing Overview

List ALL paid licenses with their exact counts in a table or bullet list format:
- License name (translated from SKU): X assigned / Y available

Comment on license utilisation and any gaps (e.g., missing security add-ons, underutilised features).

## 2. Identity & Access Management

### MFA Status
- State the exact MFA registration percentage and user counts
- Assess whether this is adequate
- **Risk Level**: Critical/High/Medium/Low

### Conditional Access
- State the number of policies (total and enabled)
- Comment on policy coverage and gaps
- **Risk Level**: Critical/High/Medium/Low

### Privileged Access
- State the exact number of Global Administrators
- List the top admin roles and member counts
- Assess whether this follows least-privilege principles
- **Risk Level**: Critical/High/Medium/Low

## 3. Microsoft Secure Score

- Current Score: X / Y (Z%)
- Identity Score: X%

### Top 10 Recommendations
List all 10 recommendations from the data with their point values. For each, briefly note the impact.

## 4. Security Test Findings (Maester)

Summarise the key themes and patterns from the Maester security tests:
- Group findings by category (Identity, Devices, Data Protection, etc.)
- Highlight the most critical failures
- Do NOT list every individual test - focus on patterns and themes
- **Overall Security Risk**: Critical/High/Medium/Low

## 5. Project Recommendations

### Immediate Actions (0-30 days)
5-7 quick wins that can be implemented immediately to address critical gaps.

### Short-term Projects (1-3 months)
3-5 projects requiring planning, testing, or change management.

### Strategic Roadmap (3-12 months)
2-3 larger initiatives for long-term security maturity improvement.

## 6. Discussion Points

Key topics for client conversation:
- Security gaps that pose business risk
- License optimisation opportunities (upgrades that unlock features, or cost savings)
- Compliance considerations
- Value of ongoing security management and monitoring
- Quick wins vs. larger transformation projects

## 7. Conclusion

Brief summary of:
- Current state assessment
- Top 3 priorities
- Recommended next steps

---

Be specific with numbers. Reference actual data points. Use blank lines for readability."""


def _zerotrust_prompt(data: dict, zt_data: dict = None) -> str:
    """Build the LLM prompt for Zero Trust analysis."""
    # Extract basic metrics from our custom collection
    metadata = data.get("metadata", {})
    identity = data.get("identity", {})
    devices = data.get("devices", {})
    applications = data.get("applications", {})
    network = data.get("network", {})
    security_score = data.get("securityScore", {})

    ca_policies = identity.get("conditionalAccess", [])
    priv_access = identity.get("privilegedAccess", {})
    device_summary = devices.get("summary", {})
    named_locations = network.get("namedLocations", [])

    # Build basic summary
    summary = f"""## Tenant Information
- Tenant: {metadata.get('tenantName', 'Unknown')}
- Assessment Date: {metadata.get('assessmentDate', 'Unknown')}

## Microsoft Secure Score
- Current Score: {security_score.get('currentScore', 'N/A')} / {security_score.get('maxScore', 'N/A')}
- Percentage: {security_score.get('percentage', 'N/A')}%

## Basic Metrics (from Graph API)
- Conditional Access Policies: {len(ca_policies)}
- Global Administrators: {priv_access.get('globalAdminCount', 'N/A')}
- Managed Devices: {device_summary.get('totalDevices', 0)} ({device_summary.get('compliant', 0)} compliant)
- Enterprise Applications: {applications.get('enterpriseApps', {}).get('total', 'N/A')}
- App Protection Policies: {len(applications.get('appProtection', []))}
- Named Locations: {len(named_locations)}
"""

    # If we have detailed Microsoft ZT assessment data, add it
    detailed_findings = ""
    if zt_data:
        test_summary = zt_data.get("TestResultSummary", {})
        tests = zt_data.get("Tests", [])

        # Categorize tests by status
        failed_tests = [t for t in tests if t.get("TestStatus") == "Failed"]
        passed_tests = [t for t in tests if t.get("TestStatus") == "Passed"]
        investigate_tests = [t for t in tests if t.get("TestStatus") == "Investigate"]

        # Group failed tests by category for better analysis
        categories = {}
        for t in failed_tests:
            cat = t.get("TestCategory", "Other")
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(t)

        detailed_findings = f"""
## Microsoft Zero Trust Assessment Results

### Test Summary
- **Identity Pillar**: {test_summary.get('IdentityPassed', 0)} passed / {test_summary.get('IdentityTotal', 0)} total ({round(test_summary.get('IdentityPassed', 0) / max(test_summary.get('IdentityTotal', 1), 1) * 100)}% pass rate)
- **Devices Pillar**: {test_summary.get('DevicesPassed', 0)} passed / {test_summary.get('DevicesTotal', 0)} total ({round(test_summary.get('DevicesPassed', 0) / max(test_summary.get('DevicesTotal', 1), 1) * 100)}% pass rate)
- **Total Failed Tests**: {len(failed_tests)}
- **Tests Requiring Investigation**: {len(investigate_tests)}

### Failed Tests by Category
"""
        # Add failed tests grouped by category
        for category, cat_tests in sorted(categories.items(), key=lambda x: len(x[1]), reverse=True):
            detailed_findings += f"\n#### {category} ({len(cat_tests)} failures)\n"
            for test in cat_tests[:5]:  # Limit to 5 per category
                pillar = test.get("TestPillar", "")
                title = test.get("TestTitle", "Unknown")
                risk = test.get("TestRisk", "Unknown")
                result = test.get("TestResult", "")[:150].replace("\n", " ")  # Truncate
                detailed_findings += f"- **[{risk}]** {title}\n"
                if result:
                    detailed_findings += f"  - Finding: {result}\n"
            if len(cat_tests) > 5:
                detailed_findings += f"  - ... and {len(cat_tests) - 5} more in this category\n"

        # Add tests needing investigation
        if investigate_tests:
            detailed_findings += f"\n### Tests Requiring Investigation\n"
            for test in investigate_tests[:5]:
                detailed_findings += f"- {test.get('TestTitle', '')} ({test.get('TestCategory', '')})\n"

    return f"""You are a Microsoft 365 security expert performing a Zero Trust assessment for an MSP client.

Analyse the following tenant configuration data and provide a structured Zero Trust maturity assessment.

{summary}
{detailed_findings}

---

CRITICAL FORMATTING RULES:
1. Use proper Markdown with # for main heading, ## for sections, ### for subsections
2. Add a BLANK LINE before and after every heading and bullet list
3. Do NOT repeat sections - each section should appear ONCE only
4. Reference SPECIFIC failed tests from the data above in your analysis

Generate the report in this EXACT structure:

# Zero Trust Assessment Report

## Executive Summary

Write 2-3 paragraphs about the tenant's Zero Trust posture and maturity level (Initial/Developing/Defined/Managed/Optimised). Reference the test pass/fail ratios.

## Assessment by Category

### Access Control

Analyse Conditional Access, MFA, and access control failures. Reference specific test failures.
- **Risk Level**: Critical/High/Medium/Low

### Credential Management

Analyse password policies, credential protection, and authentication methods.
- **Risk Level**: Critical/High/Medium/Low

### Privileged Access

Analyse admin accounts, role assignments, and privileged identity management.
- **Risk Level**: Critical/High/Medium/Low

### Device Management

Analyse device compliance, MDM, and endpoint protection.
- **Risk Level**: Critical/High/Medium/Low

### Application Security

Analyse app protection, OAuth governance, and enterprise app configuration.
- **Risk Level**: Critical/High/Medium/Low

### Data Protection

Analyse sensitivity labels, DLP, and data classification.
- **Risk Level**: Critical/High/Medium/Low

## Critical Findings

List the TOP 10 most critical security gaps from the failed tests, ordered by risk level (High risk first).

## Recommendations Roadmap

### Immediate (0-30 days)

List 3-5 quick wins based on the failed tests.

### Short-term (1-3 months)

List 3-5 important improvements.

### Medium-term (3-6 months)

List 2-3 strategic enhancements.

## Conclusion

Summarise key takeaways and next steps.

---

Be specific - reference the actual test failures. Use blank lines for readability."""


# ── startup ─────────────────────────────────────────

def _open_browser():
    import time
    time.sleep(1.5)
    try:
        webbrowser.open("http://127.0.0.1:5000")
    except Exception:
        pass  # Ignore browser open errors


if __name__ == "__main__":
    if not is_admin():
        print("[!] nmap requires Administrator privileges for OS detection (-O).")
        print("    Right-click Command Prompt → Run as administrator")
        sys.exit(1)

    # Check and install dependencies
    print("[*] Checking dependencies...")
    if not ensure_dependencies():
        print("\n[!] Some dependencies are missing. Please install them and try again.")
        sys.exit(1)
    print()

    print("[*] Technical Audit Analysis → http://127.0.0.1:5000")
    print("[*] Opening browser...")
    threading.Thread(target=_open_browser, daemon=True).start()
    print("[*] Server starting... (press Ctrl+C to stop)")
    print()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
