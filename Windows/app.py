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

from flask import Flask, Response, request, stream_with_context, render_template, send_from_directory
from scan import MSPConsultantTool, classify_target, _get_local_interfaces

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) or os.getcwd()

app = Flask(__name__)

# Only allow characters that are valid in an IP, CIDR, or hostname.
# Rejects anything that could be interpreted as nmap flags or shell metacharacters.
_TARGET_RE = re.compile(r'^[A-Za-z0-9.\-/:]+$')

# Client name: letters, digits, spaces, hyphens, underscores.  Becomes a folder name.
_CLIENT_RE = re.compile(r'^[A-Za-z0-9 _-]+$')

# Track active processes by session ID for stop functionality
_active_processes = {}


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
        from datetime import datetime
        from report_templates import NetworkTemplatedReport

        tool  = MSPConsultantTool()
        args  = tool.SCAN_PROFILES[scan_depth]
        label = scan_depth.capitalize() + " Scan"
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

        yield sse(f"[*] Target  : {target}")
        yield sse(f"[*] Scan    : {label}")
        yield sse(f"[*] Flags   : {args}")
        yield sse("")

        # Create client folder
        client_folder = os.path.join(BASE_DIR, client)
        os.makedirs(client_folder, exist_ok=True)

        # ── nmap ─────────────────────────────────────
        xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="nmap_")
        os.close(xml_fd)
        cmd  = ["nmap"] + args.split() + ["-v", "-oX", xml_path, target]
        proc = None

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True)

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

            active_data = {ip: info for ip, info in tech_data.items() if info.get("status") == "up"}
            yield sse(f"[+] Found {len(active_data)} active hosts", event="status")

            # ── Save JSON ────────────────────────────────
            safe_target = target.replace("/", "-").replace(":", "-")
            json_file = f"{client}_{safe_target}_{timestamp}.json"
            json_path = os.path.join(client_folder, json_file)
            with open(json_path, 'w') as f:
                json.dump(active_data, f, indent=4)

            # ── ALWAYS generate Python-templated structured report (instant, HTML) ──
            yield sse("[*] Generating structured report...", event="status")

            try:
                metadata = {
                    'client_name': client,
                    'target': target,
                    'scan_type': scan_type,
                    'scan_depth': scan_depth,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M")
                }
                template_report = NetworkTemplatedReport(active_data, metadata)

                # Generate standalone HTML for file (with full document structure)
                structured_report_file = template_report.generate(standalone=True)
                # Generate embedded HTML for web UI (just body content)
                structured_report_ui = template_report.generate(standalone=False)

                # Save structured report as HTML
                structured_file = f"{client}_{safe_target}_{timestamp}_report.html"
                structured_path = os.path.join(client_folder, structured_file)
                with open(structured_path, "w", encoding="utf-8") as f:
                    f.write(structured_report_file)

                yield sse(f"[✓] Structured report generated: {structured_file}", event="status")
                yield sse("")

                # Send embedded HTML to UI (no markdown parsing needed)
                yield sse(structured_report_ui, event="report_html")

            except Exception as exc:
                yield sse(f"[!] Error generating structured report: {exc}", event="scan_error")
                return

            # ── notify browser of generated files ────────
            files_data = {
                "json": f"{client}/{json_file}",
                "structured_report": f"{client}/{structured_file}",
            }

            yield sse(json.dumps(files_data), event="files")
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
        import shutil
        from datetime import datetime

        # Check for PowerShell
        pwsh_path = shutil.which("pwsh")
        if not pwsh_path:
            yield sse("PowerShell 7 (pwsh) not found.", event="zt_error")
            yield sse("Install with: brew install powershell", event="zt_error")
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

        yield sse("[*] Running Zero Trust Assessment…")
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
                cwd=BASE_DIR
            )

            # Register process for stop functionality
            if session_id:
                _active_processes[session_id] = proc

            in_output_block = False
            for line in proc.stdout:
                stripped = line.rstrip("\n")

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
            yield sse("Parsing assessment data…", event="status")
            with open(os.path.join(BASE_DIR, json_file), "r", encoding="utf-8-sig") as f:
                assessment_data = json.load(f)

            # Load detailed ZT assessment data if available (from Microsoft module)
            zt_assessment_data = None
            if zt_json_file and os.path.exists(os.path.join(BASE_DIR, zt_json_file)):
                yield sse("Loading detailed Microsoft assessment data…", event="status")
                try:
                    with open(os.path.join(BASE_DIR, zt_json_file), "r", encoding="utf-8-sig") as f:
                        zt_assessment_data = json.load(f)
                except Exception as e:
                    yield sse(f"[!] Could not load detailed data: {e}")

            # ── Generate Python-templated HTML report (instant) ──
            yield sse("Generating structured assessment report…", event="status")
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

            from report_templates import ZeroTrustTemplatedReport
            report_gen = ZeroTrustTemplatedReport(assessment_data, zt_assessment_data)

            # Generate embedded HTML for web UI
            report_html = report_gen.generate(standalone=False)
            yield sse(report_html, event="report_html")

            # Save standalone HTML report
            summary_html_file = f"zerotrust_summary_{timestamp}.html"
            summary_html_path = os.path.join(client_folder, summary_html_file)
            with open(summary_html_path, "w", encoding="utf-8") as f:
                f.write(report_gen.generate(standalone=True))

            yield sse("[+] Structured HTML report generated")

            # Notify browser of files
            files_data = {
                "json": json_file,
                "summary_html": f"{client}/{summary_html_file}",
            }
            if html_file:
                files_data["ms_html"] = html_file

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
        import shutil
        from datetime import datetime

        # Check for PowerShell
        pwsh_path = shutil.which("pwsh")
        if not pwsh_path:
            yield sse("PowerShell 7 (pwsh) not found.", event="ari_error")
            yield sse("Install with: brew install powershell", event="ari_error")
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
                cwd=BASE_DIR
            )

            # Register process for stop functionality
            if session_id:
                _active_processes[session_id] = proc

            # Regex to strip ANSI escape codes
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

            in_output_block = False
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                # Remove ANSI color codes
                stripped = ansi_escape.sub('', stripped)

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
            with open(os.path.join(BASE_DIR, json_file), "r", encoding="utf-8-sig") as f:
                inventory_data = json.load(f)

            # ── Generate Python-templated HTML report (instant) ──
            yield sse("Generating structured inventory report...", event="status")
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
            ari_folder = os.path.join(client_folder, "AzureInventory")

            from report_templates import AzureTemplatedReport
            report_gen = AzureTemplatedReport(inventory_data)

            # Generate embedded HTML for web UI
            report_html = report_gen.generate(standalone=False)
            yield sse(report_html, event="report_html")

            # Save standalone HTML report
            html_file = f"azureinventory_report_{timestamp}.html"
            html_path = os.path.join(ari_folder, html_file)
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(report_gen.generate(standalone=True))

            yield sse("[+] Structured HTML report generated")

            # Notify browser of files
            files_data = {
                "json": json_file,
                "html": f"{client}/AzureInventory/{html_file}",
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


# ── M365 Assessment ───────────────────────────────────────────────────────────

@app.route("/m365assessment")
def m365assessment():
    client = request.args.get("client", "").strip()
    session_id = request.args.get("session", "").strip()
    skip_maester = request.args.get("skipMaester", "").lower() == "true"
    update_maester_tests = request.args.get("updateMaesterTests", "").lower() == "true"

    if not client or not _CLIENT_RE.match(client):
        return Response(sse("Invalid or missing client name.", event="m365_error"),
                        mimetype="text/event-stream")

    def generate():
        import shutil
        from datetime import datetime

        # Check for PowerShell
        pwsh_path = shutil.which("pwsh")
        if not pwsh_path:
            yield sse("PowerShell 7 (pwsh) not found.", event="m365_error")
            yield sse("Install with: brew install powershell", event="m365_error")
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

        if update_maester_tests:
            cmd.append("-UpdateMaesterTests")

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
                cwd=BASE_DIR
            )

            # Register process for stop functionality
            if session_id:
                _active_processes[session_id] = proc

            # Regex to strip ANSI escape codes
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

            in_output_block = False
            for line in proc.stdout:
                stripped = line.rstrip("\n")
                # Remove ANSI color codes
                stripped = ansi_escape.sub('', stripped)

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
            with open(os.path.join(BASE_DIR, json_file), "r", encoding="utf-8-sig") as f:
                assessment_data = json.load(f)

            # Generate Python-templated structured report (instant, HTML)
            yield sse(f"[*] Generating structured report...", event="status")

            try:
                from report_templates import M365TemplatedReport
                template_report = M365TemplatedReport(assessment_data)

                # Generate standalone HTML for file (with full document structure)
                structured_report_file = template_report.generate(standalone=True)
                # Generate embedded HTML for web UI (just body content)
                structured_report_ui = template_report.generate(standalone=False)

                # Save structured report as HTML
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
                structured_file = f"m365assessment_structured_{timestamp}.html"
                structured_path = os.path.join(client_folder, structured_file)
                with open(structured_path, "w", encoding="utf-8") as f:
                    f.write(structured_report_file)

                yield sse(f"[✓] Structured report generated: {structured_file}", event="status")
                yield sse("")

                # Send embedded HTML to UI (no markdown parsing needed)
                yield sse(structured_report_ui, event="report_html")

            except Exception as exc:
                yield sse(f"[!] Error generating structured report: {exc}", event="m365_error")
                return

            # Notify browser of files
            files_data = {
                "json": json_file,
                "structured_report": f"{client}/{structured_file}",
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


# ── startup ─────────────────────────────────────────

def _open_browser():
    import time
    time.sleep(1)
    webbrowser.open("http://127.0.0.1:5000")


if __name__ == "__main__":
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] nmap requires Administrator for OS detection (-O).")
        print("    Right-click run.bat and select 'Run as administrator'")
        sys.exit(1)

    print("[*] Discovery Tool → http://127.0.0.1:5000")
    threading.Thread(target=_open_browser, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
