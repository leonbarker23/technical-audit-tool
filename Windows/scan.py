import subprocess
import tempfile
import xml.etree.ElementTree as ET
import json
import os
import re
import sys
import ipaddress
import ctypes
import shutil
import urllib.request
from datetime import datetime

# Import ollama lazily after ensuring it's installed
ollama = None

# Default model — smaller footprint for Windows machines
DEFAULT_MODEL = "qwen2.5:7b"


def is_admin():
    """Check if running with Administrator privileges (Windows)."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _find_python():
    """Check if Python is available."""
    for cmd in ['python', 'python3', 'py']:
        if shutil.which(cmd):
            return cmd
    return None


def _install_python():
    """Install Python via winget or prompt for manual install."""
    print("[*] Python not found. Attempting to install via winget...")

    if not shutil.which('winget'):
        print("[!] winget not available. Please install Python manually:")
        print("    https://www.python.org/downloads/")
        print("    IMPORTANT: Check 'Add Python to PATH' during installation!")
        return False

    try:
        result = subprocess.run(
            ['winget', 'install', '--id', 'Python.Python.3.12', '-e', '--accept-source-agreements', '--accept-package-agreements'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("[+] Python installed successfully!")
            print("[i] IMPORTANT: Close and reopen your terminal for PATH changes to take effect.")
            return True
        else:
            print(f"[!] winget install failed: {result.stderr}")
            print("[!] Please install Python manually from https://www.python.org/downloads/")
            return False
    except Exception as e:
        print(f"[!] Error installing Python: {e}")
        return False


def _find_nmap():
    """Return nmap executable path, checking common Windows install locations."""
    if shutil.which('nmap'):
        return 'nmap'
    for path in [
        r'C:\Program Files (x86)\Nmap\nmap.exe',
        r'C:\Program Files\Nmap\nmap.exe',
    ]:
        if os.path.exists(path):
            return path
    return None


def _install_nmap():
    """Install nmap via winget (Windows 10+) or prompt for manual install."""
    print("[*] nmap not found. Attempting to install via winget...")

    # Check if winget is available
    if not shutil.which('winget'):
        print("[!] winget not available. Please install nmap manually:")
        print("    https://nmap.org/download.html")
        print("    Download and run the Windows installer, then restart this script.")
        return False

    try:
        # Install nmap via winget
        result = subprocess.run(
            ['winget', 'install', '--id', 'Insecure.Nmap', '-e', '--accept-source-agreements', '--accept-package-agreements'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print("[+] nmap installed successfully!")
            print("[i] You may need to restart your terminal for PATH changes to take effect.")
            return True
        else:
            print(f"[!] winget install failed: {result.stderr}")
            print("[!] Please install nmap manually from https://nmap.org/download.html")
            return False
    except Exception as e:
        print(f"[!] Error installing nmap: {e}")
        return False


def _find_ollama():
    """Return ollama executable path."""
    if shutil.which('ollama'):
        return 'ollama'
    for path in [
        os.path.expandvars(r'%LOCALAPPDATA%\Programs\Ollama\ollama.exe'),
        r'C:\Program Files\Ollama\ollama.exe',
    ]:
        expanded = os.path.expandvars(path)
        if os.path.exists(expanded):
            return expanded
    return None


def _install_ollama():
    """Download and install Ollama for Windows."""
    print("[*] Ollama not found. Downloading installer...")

    installer_url = "https://ollama.com/download/OllamaSetup.exe"
    installer_path = os.path.join(tempfile.gettempdir(), "OllamaSetup.exe")

    try:
        # Download the installer
        print(f"    Downloading from {installer_url}...")
        urllib.request.urlretrieve(installer_url, installer_path)
        print("[+] Download complete.")

        # Run the installer
        print("[*] Running Ollama installer (follow the prompts)...")
        subprocess.run([installer_path], check=True)
        print("[+] Ollama installation complete!")

        # Clean up
        if os.path.exists(installer_path):
            os.unlink(installer_path)

        return True
    except Exception as e:
        print(f"[!] Error installing Ollama: {e}")
        print("[!] Please install manually from https://ollama.com/download")
        return False


def _ensure_ollama_model(model_name):
    """Ensure the specified Ollama model is pulled."""
    ollama_exe = _find_ollama()
    if not ollama_exe:
        return False

    print(f"[*] Checking for model '{model_name}'...")

    try:
        # Check if model exists
        result = subprocess.run(
            [ollama_exe, 'list'],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if model_name in result.stdout:
            print(f"[+] Model '{model_name}' is available.")
            return True

        # Pull the model - run without capturing output to avoid encoding issues
        # Ollama's progress bars use special characters that break Windows CMD
        print(f"[*] Pulling model '{model_name}' (this may take a while)...")
        print(f"    Progress will display below:")
        result = subprocess.run(
            [ollama_exe, 'pull', model_name],
            # Don't capture output - let it display directly to console
        )

        if result.returncode == 0:
            print(f"[+] Model '{model_name}' pulled successfully!")
            return True
        else:
            print(f"[!] Failed to pull model '{model_name}'")
            return False
    except Exception as e:
        print(f"[!] Error checking/pulling model: {e}")
        return False


def ensure_dependencies(model_name=DEFAULT_MODEL):
    """Check and install nmap and Ollama if missing. Returns True if all ready."""
    all_ok = True

    # Check nmap
    if not _find_nmap():
        if not _install_nmap():
            all_ok = False
        elif not _find_nmap():
            print("[!] nmap installed but not found in PATH. Please restart your terminal.")
            all_ok = False

    # Check Ollama
    if not _find_ollama():
        if not _install_ollama():
            all_ok = False
        elif not _find_ollama():
            print("[!] Ollama installed but not found. Please restart your terminal.")
            all_ok = False

    # Ensure model is pulled (only if Ollama is available)
    if _find_ollama():
        if not _ensure_ollama_model(model_name):
            all_ok = False

    return all_ok

class MSPConsultantTool:
    SCAN_PROFILES = {
        "deep":   "-sV -O -sC -T4",                   # full version + OS + default scripts
        "medium": "-sV -O -T4 --min-rate 500",        # version + OS, no scripts, moderate speed
        "fast":   "-T5 --top-ports 100 --min-rate 1000", # top 100 ports, no version/OS, max speed
    }

    def __init__(self, model_name=DEFAULT_MODEL):
        self.model = model_name
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")

    def run_discovery(self, target, scan_type):
        label = "Deep Scan" if scan_type == "single" else "Broad Discovery"
        args = self.SCAN_PROFILES[scan_type]
        print(f"[*] Phase 1: {label} on {target}...")
        print(f"    Flags: {args}\n")

        # -v: report ports as they're found (live output)
        # -oX: structured XML written to a temp file in parallel
        xml_fd, xml_path = tempfile.mkstemp(suffix='.xml', prefix='nmap_')
        os.close(xml_fd)

        nmap_exe = _find_nmap() or 'nmap'
        cmd = [nmap_exe] + args.split() + ["-v", "-oX", xml_path, target]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            for line in proc.stdout:
                print(line, end='', flush=True)
            proc.wait()

            if proc.returncode != 0:
                print(f"\n[!] nmap exited with code {proc.returncode}")
                return {}

            return self._parse_nmap_xml(xml_path)
        finally:
            if os.path.exists(xml_path):
                os.unlink(xml_path)

    def _parse_nmap_xml(self, xml_path):
        tree = ET.parse(xml_path)
        root = tree.getroot()
        technical_data = {}

        for host_elem in root.findall('host'):
            address = host_elem.find("address[@addrtype='ipv4']")
            if address is None:
                continue
            ip = address.get('addr')

            hostname_elem = host_elem.find('.//hostname')
            hostname = hostname_elem.get('name', '') if hostname_elem is not None else ''

            status_elem = host_elem.find('status')
            status = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'

            osmatch   = host_elem.findall('.//osmatch')
            top_os    = osmatch[0] if osmatch else None
            os_name     = top_os.get('name',     'Unknown') if top_os is not None else 'Unknown'
            os_vendor   = top_os.get('vendor',   'Unknown') if top_os is not None else 'Unknown'
            os_accuracy = top_os.get('accuracy', '0')       if top_os is not None else '0'

            protocols = {}
            for port_elem in host_elem.findall('.//port'):
                proto    = port_elem.get('protocol')
                port_num = int(port_elem.get('portid'))

                state_elem   = port_elem.find('state')
                service_elem = port_elem.find('service')
                state     = state_elem.get('state', 'unknown')        if state_elem   is not None else 'unknown'
                svc_name  = service_elem.get('name', '')              if service_elem is not None else ''
                product   = service_elem.get('product', '')           if service_elem is not None else ''
                version   = service_elem.get('version', '')           if service_elem is not None else ''
                extrainfo = service_elem.get('extrainfo', '')         if service_elem is not None else ''

                protocols.setdefault(proto, []).append({
                    "port":      port_num,
                    "name":      svc_name,
                    "product":   product,
                    "version":   version,
                    "extrainfo": extrainfo,
                    "state":     state
                })

            technical_data[ip] = {
                "hostname":    hostname,
                "vendor":      os_vendor,
                "os":          os_name,
                "os_accuracy": int(os_accuracy),
                "status":      status,
                "protocols":   protocols
            }

        return technical_data

    def _build_summary(self, tech_data):
        summary = ""
        no_data_ips = []

        for ip, details in tech_data.items():
            if not details['protocols']:
                no_data_ips.append(ip)
                continue
            summary += f"\nHost: {ip} | Hostname: {details['hostname'] or 'unknown'} | Vendor: {details['vendor']} | OS: {details['os']} (accuracy: {details['os_accuracy']}%)\n"
            for proto, services in details['protocols'].items():
                for svc in services:
                    product_str = f"{svc['product']} {svc['version']}".strip()
                    summary += f"  - {proto}/{svc['port']}  {svc['state']}  {svc['name']}"
                    if product_str:
                        summary += f"  [{product_str}]"
                    if svc['extrainfo']:
                        summary += f"  ({svc['extrainfo']})"
                    summary += "\n"

        if no_data_ips:
            summary += f"\n[{len(no_data_ips)} hosts responded to ping but had no open ports detected: {', '.join(no_data_ips[:10])}"
            if len(no_data_ips) > 10:
                summary += f" … and {len(no_data_ips) - 10} more"
            summary += "]\n"

        return summary

    def _prompt_single(self, summary):
        return f"""You are a security analyst writing a formal host security assessment report.
Analyse the scan data below and produce your output EXACTLY in the markdown structure shown in the OUTPUT TEMPLATE.
Do NOT add any text outside that structure. Do NOT invent a header block — that is added by the caller.
Every open or filtered port must appear somewhere in the findings. Do not skip or summarise away any service.

SCAN DATA:
{summary}

SERVICES TO EVALUATE EXPLICITLY (do not omit any that appear in the data):
- SNMP (port 161): flag if present — default community strings ("public") are trivially exploitable.
- NFS (port 2049) and rpcbind (port 111): flag together — rpcbind is the prerequisite attack path into NFS.
- SMB/Samba (ports 139, 445): assess for credential relay, enumeration, and unauthorised share access.
- Management interfaces (e.g. Proxmox, router admin panels): these are high-value targets.
- Network printers (ports 515, 631, 9100): flag — printers are common pivot points and often unpatched.
- SSH: note version; flag default-credential risk on embedded devices.
- Filtered ports: note them — a service may be reachable under different conditions.

OUTPUT TEMPLATE (fill in every section — use real values, not placeholder text):

## Executive Summary

[1-3 sentences: what this host is, what was found, overall risk rating as one of: Critical / High / Medium-High / Medium / Low.]

**Overall Risk Rating: [RATING]**

---

## Host Findings

### 1. [Short title] ([RISK LEVEL] RISK)

**Finding:** [What was observed — service, port, version, state.]

**Risk:** [Why this matters — what an attacker could do.]

**Recommendation:** [Concrete action(s) to fix or mitigate.]

---

[Repeat ### blocks for every distinct finding, numbered sequentially. Group related ports into one finding where logical (e.g. all NFS/RPC ports together). Each finding MUST include Finding / Risk / Recommendation.]

---

## Informational Observations

[Note any version observations, services that are normal/expected, or anything that does not warrant its own finding block but is worth recording.]

---

## Recommendations Summary

| Priority | Action | Effort |
|----------|--------|--------|
| **[High/Medium/Low]** | [Action] | [Low / Medium / High / Ongoing] |

[One row per recommendation, ordered High → Medium → Low.]

---

## Next Steps

[2-4 bullet points: what follow-up assessment work would be valuable for this host.]"""

    def _prompt_subnet(self, summary, active_host_count):
        return f"""You are a security analyst writing a formal network security assessment report.
Analyse the scan data below and produce your output EXACTLY in the markdown structure shown in the OUTPUT TEMPLATE.
Do NOT add any text outside that structure. Do NOT invent a header block — that is added by the caller.
CRITICAL: Every IP address, hostname, port number, service name, count, and category in your output MUST come directly from the SCAN DATA provided. Do NOT invent, guess, or assume any details that are not present in the data. If information is not available, say so explicitly.
Every exposed service category must appear somewhere in the findings. Do not skip or summarise away any service class.

SCAN DATA:
{summary}

ACTIVE HOST COUNT: {active_host_count}

SERVICES TO EVALUATE EXPLICITLY (do not omit any that appear in the data):
- SNMP (port 161): flag if present — default community strings ("public") are trivially exploitable.
- NFS (port 2049) and rpcbind (port 111): flag together — rpcbind is the prerequisite attack path into NFS.
- SMB/Samba (ports 139, 445): assess for credential relay, enumeration, and unauthorised share access.
- Network management interfaces (e.g. Proxmox on 3128, router admin on 7443/8080/8443): these are high-value targets.
- Network printers (ports 515, 631, 9100): flag — printers are common pivot points and often unpatched.
- SSH: note any outdated versions; flag default-credential risk on embedded devices (switches, APs).
- Filtered ports: note them — they indicate a service that may be reachable under different conditions.
- Devices that are up but have no detected open ports: note them in Informational Observations.

NOISE TO DE-PRIORITISE:
- Apple AirPlay / Bonjour ports (5000, 7000, 7100, 49152, 62078) on iOS/macOS/tvOS devices are normal home-network services. Do not flag these as vulnerabilities unless there is a known CVE. List them once under Informational Observations instead.

OUTPUT TEMPLATE (fill in every section — use real IPs, hostnames, ports, and values from the scan data):

## Executive Summary

[2-4 sentences: what the network looks like, how many hosts had open ports vs how many had none, and the single biggest risk at a glance. Use ONLY the numbers from ACTIVE HOST COUNT and the scan data — do not invent figures.]

**Overall Risk Rating: [RATING — one of: Critical / High / Medium-High / Medium / Low]**

[1 sentence explaining why that rating.]

---

## Network Inventory Summary

| Category | Count | Examples |
|----------|-------|----------|
| [Category name] | [n] | [Specific hostnames or IPs] |

[Classify ONLY the hosts you have actual port/service data for. Do NOT guess or invent categories for hosts you cannot see. Hosts that responded to ping but had no ports detected must appear as a single "No Ports Detected" row with the exact count from the scan data. Use categories like: Network Infrastructure, Servers / Virtualisation, IoT / Smart Home, Media Devices, Personal Devices, Printers, No Ports Detected. CRITICAL: every count and IP in this table must come directly from the SCAN DATA above — do not make up numbers.]

---

## Critical Findings

### 1. [Short descriptive title] ([RISK LEVEL] RISK)

**Finding:** [What was observed — be specific about hosts, services, ports, versions.]

**Risk:** [Why this matters — what an attacker could actually do if this is exploited.]

**Recommendation:** [Concrete action(s). If multiple hosts are affected, say so explicitly.]

---

[Repeat ### blocks for every distinct finding, numbered sequentially. Group related services into one finding where logical (e.g. all NFS + rpcbind + nlockmgr together on the same hosts). Each finding MUST have Finding / Risk / Recommendation. Order findings by severity: High first, then Medium, then Low.]

---

## Informational Observations

### Devices Without Identified Services
[List any up-hosts with no open TCP ports detected. Note hostname if known, and any likely purpose.]

### Software Version Notes
[Note any services running on older-but-supported versions, or where the full version could not be determined.]

### Expected Services
[Briefly note any services that are normal for this environment and were intentionally not flagged (e.g. AirPlay on Apple devices).]

---

## Recommendations Summary

| Priority | Action | Effort |
|----------|--------|--------|
| **[High/Medium/Low]** | [Action — be specific about which hosts] | [Low / Medium / High / Ongoing] |

[One row per recommendation, ordered High → Medium → Low. Must match the findings above.]

---

## Discussion Points

[5-7 numbered questions an analyst would want answered by the network owner before proceeding. Ground them in what was actually observed in the scan (e.g. reference specific hosts, services, or gaps).]

---

## Next Steps

[3-4 bullet points: what follow-up assessment work is recommended. Use standard terms: Vulnerability Assessment, Configuration Review, Penetration Test, Segmentation Design, etc.]

---

*This report is based on unauthenticated network discovery only. An authenticated assessment would provide additional depth and accuracy.*"""

    def get_vulnerability_report(self, tech_data, scan_type):
        global ollama
        if ollama is None:
            import ollama as _ollama
            ollama = _ollama

        phase_label = "Host Vulnerability Report" if scan_type == "single" else "Network Vulnerability Report"
        print(f"[*] Phase 2: Generating {phase_label} via {self.model}...")

        active_data = {ip: info for ip, info in tech_data.items() if info.get("status") == "up"}
        summary = self._build_summary(active_data)
        prompt = (self._prompt_single(summary)
                  if scan_type == "single"
                  else self._prompt_subnet(summary, len(active_data)))

        try:
            response = ollama.generate(model=self.model, prompt=prompt)
            return response['response']
        except Exception as e:
            print(f"[!] Ollama error: {e}")
            print(f"    Ensure ollama is running and '{self.model}' is pulled (ollama pull {self.model})")
            return None

    def _build_technical_table(self, tech_data):
        lines = []
        lines.append("| IP Address | Hostname | Vendor | OS | Port | Protocol | State | Service | Product |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for ip, details in tech_data.items():
            if not details['protocols']:
                # Host is up but no ports were detected — still include it
                lines.append(f"| {ip} | {details['hostname'] or '—'} | {details['vendor']} | {details['os']} | — | — | — | — | — |")
                continue
            for proto, services in details['protocols'].items():
                for svc in services:
                    product_str = f"{svc['product']} {svc['version']}".strip()
                    lines.append(f"| {ip} | {details['hostname'] or '—'} | {details['vendor']} | {details['os']} | {svc['port']} | {proto} | {svc['state']} | {svc['name']} | {product_str or '—'} |")
        return "\n".join(lines)

    def save_outputs(self, tech_data, vuln_report, scan_type, client_name="default", target=""):
        # Only persist hosts that are actually up
        active_data = {ip: info for ip, info in tech_data.items() if info.get("status") == "up"}

        # ── client output folder ─────────────────────────
        out_dir = os.path.join(os.getcwd(), client_name)
        os.makedirs(out_dir, exist_ok=True)

        # ── sanitise target for use in filename ──────────
        # Replace characters unsafe for filenames: / → - and : → -
        safe_target = target.replace("/", "-").replace(":", "-") if target else "unknown"

        # Save Technical JSON (active hosts only)
        json_file = f"{client_name}_{safe_target}_{self.timestamp}.json"
        with open(os.path.join(out_dir, json_file), 'w') as f:
            json.dump(active_data, f, indent=4)

        # ── Markdown report ──────────────────────────────
        report_title = "Host Security Assessment Report" if scan_type == "single" else "Network Security Assessment Report"
        assessment_date = datetime.now().strftime("%d %B %Y")
        md_file = f"{client_name}_{safe_target}_{self.timestamp}.md"

        with open(os.path.join(out_dir, md_file), 'w') as f:
            # --- formal header (script-generated, never from LLM) ---
            f.write(f"# {report_title}\n\n")
            f.write(f"**Client:** {client_name}  \n")
            f.write(f"**Assessment Date:** {assessment_date}  \n")
            f.write(f"**Prepared By:** Security Analysis Team  \n")
            f.write(f"**Classification:** Confidential\n\n")
            f.write("---\n\n")

            # --- LLM-generated body (Executive Summary … Next Steps) ---
            if vuln_report:
                f.write(vuln_report)
            else:
                f.write("*Analysis unavailable — see technical data in the JSON output.*\n")

            # --- appendix: raw port-level technical table ---
            f.write("\n\n---\n\n")
            f.write("## Appendix: Port-Level Technical Data\n\n")
            f.write(self._build_technical_table(active_data))
            f.write("\n")

        print(f"\n[+] Files generated in '{client_name}/':")
        print(f"    - Technical Data: {json_file}")
        print(f"    - Report:         {md_file}")

        return json_file, md_file

def _get_local_interfaces():
    """Detect local IPv4 addresses and subnets using PowerShell (Windows)."""
    results = []
    try:
        cmd = ['powershell', '-Command',
               "Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json"]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL,
                                         creationflags=subprocess.CREATE_NO_WINDOW)
        data = json.loads(output)

        # Handle single result (not a list)
        if isinstance(data, dict):
            data = [data]

        for entry in data:
            ip = entry.get('IPAddress', '')
            if ip == '127.0.0.1':
                continue
            iface = entry.get('InterfaceAlias', 'Unknown')
            prefix = entry.get('PrefixLength', 24)
            network = ipaddress.IPv4Network(f'{ip}/{prefix}', strict=False)
            results.append((iface, ip, str(network)))
    except Exception:
        pass
    return results

def classify_target(target):
    """Return 'single' (IP or hostname) or 'subnet', or None if unresolvable."""
    import socket

    # Bare IP address (no prefix)?
    try:
        ipaddress.ip_address(target)
        return "single"
    except ValueError:
        pass

    # CIDR notation?
    try:
        network = ipaddress.ip_network(target, strict=False)
        return "single" if network.prefixlen >= 29 else "subnet"
    except ValueError:
        pass

    # Hostname — attempt DNS resolution
    try:
        socket.gethostbyname(target)
        return "single"
    except socket.gaierror:
        return None

def get_target():
    interfaces = _get_local_interfaces()
    if interfaces:
        print("\n[i] Local Interfaces:")
        for name, ip, network in interfaces:
            print(f"    {name:<6} {ip:<16} {network}")
    else:
        print("\n[i] Could not detect local interfaces.")

    while True:
        target = input("\n[?] Enter target (IP, hostname, or subnet): ").strip()
        if not target:
            print("    Target cannot be empty.")
            continue
        scan_type = classify_target(target)
        if scan_type is None:
            print(f"    '{target}' could not be resolved. Check the address and try again.")
            continue
        label = "single host — deep scan" if scan_type == "single" else "subnet — broad scan"
        print(f"    [>] Detected: {label}")
        return target, scan_type

_CLIENT_RE = re.compile(r'^[A-Za-z0-9 _-]+$')

def get_client():
    while True:
        name = input("\n[?] Enter client name: ").strip()
        if not name:
            print("    Client name cannot be empty.")
            continue
        if not _CLIENT_RE.match(name):
            print("    Only letters, digits, spaces, hyphens and underscores are allowed.")
            continue
        return name

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

    client_name  = get_client()
    target, scan_type = get_target()
    tool = MSPConsultantTool()

    tech_results = tool.run_discovery(target, scan_type)
    if not tech_results:
        print("[!] No hosts found. Verify the target and that you have network access.")
        sys.exit(1)

    vuln_report = tool.get_vulnerability_report(tech_results, scan_type)
    if vuln_report is None:
        print("[!] Skipping vulnerability report — falling back to technical output only.")
    tool.save_outputs(tech_results, vuln_report, scan_type, client_name, target)