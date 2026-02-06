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


# ── startup ─────────────────────────────────────────

def _open_browser():
    import time
    time.sleep(1)
    webbrowser.open("http://127.0.0.1:5000")


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

    print("[*] Discovery Tool → http://127.0.0.1:5000")
    threading.Thread(target=_open_browser, daemon=True).start()
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
