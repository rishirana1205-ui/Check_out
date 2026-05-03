"""
Vulnerability Scanner — Flask Web Server
=========================================
REST API and web dashboard for the vulnerability scanner.
"""

import uuid
import threading
from flask import Flask, render_template, jsonify, request
from scanner_engine import VulnScanner, PORT_PRESETS
from report_generator import generate_report

app = Flask(__name__)

# In-memory scan storage
scans = {}


@app.route("/")
def index():
    """Serve the web dashboard."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Launch a new vulnerability scan."""
    data = request.get_json(force=True) if request.is_json else request.form.to_dict()

    target = data.get("target", "127.0.0.1").strip()
    port_preset = data.get("port_preset", "quick")
    custom_ports_str = data.get("custom_ports", "")
    timeout = float(data.get("timeout", 1.5))

    # Parse custom ports if provided
    custom_ports = None
    if custom_ports_str:
        try:
            custom_ports = []
            for part in custom_ports_str.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = part.split("-", 1)
                    custom_ports.extend(range(int(start), int(end) + 1))
                else:
                    custom_ports.append(int(part))
        except ValueError:
            return jsonify({"error": "Invalid custom port format. Use: 80,443,8080 or 1-1024"}), 400

    scan_id = str(uuid.uuid4())[:8]
    scanner = VulnScanner(target, port_preset, custom_ports, timeout)

    scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "status": "running",
        "progress": 0,
        "phase": "Initializing...",
        "results": None,
        "report": None,
    }

    def run_scan():
        def on_progress(status):
            scans[scan_id]["status"] = status["status"]
            scans[scan_id]["progress"] = status["progress"]
            scans[scan_id]["phase"] = status["phase"]

        results = scanner.run(progress_callback=on_progress)

        if isinstance(results, dict) and "scan_info" in results:
            report = generate_report(results)
            scans[scan_id]["results"] = results
            scans[scan_id]["report"] = report
            scans[scan_id]["status"] = "completed"
            scans[scan_id]["progress"] = 100
            scans[scan_id]["phase"] = "Scan complete"
        else:
            scans[scan_id]["status"] = results.get("status", "error")
            scans[scan_id]["phase"] = results.get("phase", "Unknown error")

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id, "message": "Scan started"})


@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    """Get the current status of a scan."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({
        "id": scan["id"],
        "target": scan["target"],
        "status": scan["status"],
        "progress": scan["progress"],
        "phase": scan["phase"],
    })


@app.route("/api/scan/<scan_id>/results")
def scan_results(scan_id):
    """Get the results of a completed scan."""
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    if scan["status"] != "completed":
        return jsonify({"error": "Scan not yet completed", "status": scan["status"]}), 202
    return jsonify(scan["report"])


@app.route("/api/reports")
def list_reports():
    """List all completed scans."""
    reports = []
    for sid, scan in scans.items():
        reports.append({
            "id": sid,
            "target": scan["target"],
            "status": scan["status"],
            "progress": scan["progress"],
        })
    return jsonify(reports)


@app.route("/api/presets")
def get_presets():
    """Get available port presets."""
    return jsonify({k: {"count": len(v), "ports": v[:20]} for k, v in PORT_PRESETS.items()})


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  VULNERABILITY SCANNER v1.0")
    print("  Dashboard: http://127.0.0.1:5000")
    print("=" * 60)
    print("\n  WARNING: Only scan systems you own or have")
    print("  explicit authorization to test!\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
