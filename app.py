"""
NETGUARD — Network Security & ARP Threat Detection System
Web Application & REST API Service (Flask)
"""

import sys
import os
import csv
import io

# Auto-resolve venv site-packages if executed with global system Python
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
venv_site = os.path.join(BASE_DIR, "venv", "Lib", "site-packages")
if os.path.exists(venv_site) and venv_site not in sys.path:
    sys.path.insert(0, venv_site)

from flask import Flask, render_template, jsonify, request, Response, send_from_directory

from database import (
    initialize_database,
    get_devices,
    get_events,
    get_stats,
    acknowledge_event,
    update_event_status,
    sync_real_network_devices,
    simulate_arp_attack,
    clear_database
)

from pdf_generator import (
    generate_devices_pdf,
    generate_events_pdf,
    generate_dossier_pdf
)

from monitor import monitor

# Resolve directories cleanly
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR,
    static_folder=STATIC_DIR,
    static_url_path="/static"
)

# Ensure database tables and columns are properly configured on startup
initialize_database()

# Populate with real network devices on first startup
sync_real_network_devices()


@app.route("/")
def index():
    """Render the NETGUARD metallic silver control center dashboard."""
    return render_template("index.html")


@app.route("/api/interfaces")
def interfaces():
    """Return list of host network interfaces with human-readable labels."""
    return jsonify(monitor.get_interfaces())


@app.route("/api/status")
def status():
    """Return operational state and telemetry of the packet capture engine."""
    return jsonify({
        "running": monitor.running,
        "interface": monitor.interface,
        "error": monitor.last_error,
        "packet_count": monitor.packet_count,
        "start_time": monitor.start_time
    })


@app.route("/api/devices")
def devices():
    """Return inventory of all discovered network devices."""
    return jsonify(get_devices())


@app.route("/api/events")
def events():
    """Return list of logged security events and ARP mapping anomalies."""
    return jsonify(get_events())


@app.route("/api/stats")
def stats():
    """Return top-level metric counters for the executive overview."""
    stats_data = get_stats()
    stats_data["running"] = monitor.running
    stats_data["packet_count"] = monitor.packet_count
    return jsonify(stats_data)


@app.route("/api/start", methods=["POST"])
def start_monitoring():
    """Start passive packet monitoring on the chosen network interface."""
    data = request.get_json(silent=True) or {}
    interface = data.get("interface")

    if not interface:
        return jsonify({
            "success": False,
            "message": "Please select a network interface from the dropdown."
        }), 400

    available_interfaces = monitor.get_interfaces()
    if interface not in available_interfaces and len(available_interfaces) > 0:
        interface = available_interfaces[0]

    if monitor.running:
        return jsonify({
            "success": False,
            "message": "Monitoring engine is already active."
        }), 400

    started = monitor.start(interface)
    if not started:
        return jsonify({
            "success": False,
            "message": "Unable to initialize capture engine on selected interface."
        }), 500

    return jsonify({
        "success": True,
        "message": f"Real-time monitoring initialized on: {interface}"
    })


@app.route("/api/stop", methods=["POST"])
def stop_monitoring():
    """Halt active packet monitoring."""
    monitor.stop()
    return jsonify({
        "success": True,
        "message": "Monitoring engine stopped. System is on standby."
    })


@app.route("/api/events/<int:event_id>/ack", methods=["POST"])
def ack_event(event_id):
    """Acknowledge a security event."""
    success = acknowledge_event(event_id)
    if success:
        return jsonify({
            "success": True,
            "message": f"Event #{event_id} marked as acknowledged."
        })
    return jsonify({
        "success": False,
        "message": f"Event #{event_id} could not be found."
    }), 404


@app.route("/api/events/<int:event_id>/status", methods=["POST"])
def set_event_status(event_id):
    """Update investigation status for an event (e.g. 'False Positive', 'Confirmed')."""
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "Acknowledged")
    success = update_event_status(event_id, new_status)
    if success:
        return jsonify({
            "success": True,
            "message": f"Event #{event_id} investigation status set to: {new_status}"
        })
    return jsonify({
        "success": False,
        "message": f"Event #{event_id} could not be updated."
    }), 404


@app.route("/api/scan", methods=["POST"])
@app.route("/api/demo", methods=["POST"])
def scan_network():
    """Scans and synchronizes 100% REAL network devices from the local subnet & ARP table."""
    count = sync_real_network_devices()
    return jsonify({
        "success": True,
        "count": count,
        "message": f"Real network scanned: {count} live hardware devices discovered."
    })


@app.route("/api/simulate-attack", methods=["POST"])
def test_attack():
    """Simulates a controlled ARP Cache Poisoning attack against the Gateway for demonstration."""
    simulate_arp_attack()
    return jsonify({
        "success": True,
        "message": "Simulated ARP spoofing attack launched against Gateway (172.100.0.1). Detection alert recorded!"
    })


@app.route("/api/reset", methods=["POST"])
def reset_database():
    """Clear database tables."""
    clear_database()
    return jsonify({
        "success": True,
        "message": "Database tables successfully cleared."
    })


@app.route("/api/export")
@app.route("/api/export/<export_type>")
def export_data(export_type=None):
    """
    Generate and stream RFC-compliant CSV files or route to PDF exporter if requested.
    """
    fmt = request.args.get("format", "").lower()
    if fmt == "pdf":
        return export_pdf(export_type)

    target = export_type or request.args.get("type", "events")

    output = io.StringIO()
    writer = csv.writer(output)

    if target == "devices":
        devices_list = get_devices()
        writer.writerow(["ID", "IP Address", "MAC Address", "Hostname", "Vendor", "First Seen", "Last Seen", "Observations", "Status"])
        for d in devices_list:
            writer.writerow([
                d.get("id"),
                d.get("ip"),
                d.get("mac"),
                d.get("hostname"),
                d.get("vendor"),
                d.get("first_seen"),
                d.get("last_seen"),
                d.get("observations"),
                d.get("status")
            ])
        filename = "netguard_device_inventory.csv"

    else:
        events_list = get_events()
        writer.writerow(["ID", "Timestamp", "Event Type", "Severity", "IP Address", "Previous MAC", "Observed MAC", "Description", "Investigation Status", "Acknowledged"])
        for e in events_list:
            writer.writerow([
                e.get("id"),
                e.get("timestamp"),
                e.get("type"),
                e.get("severity"),
                e.get("ip"),
                e.get("previous_mac"),
                e.get("mac"),
                e.get("description"),
                e.get("investigation_status"),
                "Yes" if e.get("acknowledged") else "No"
            ])
        filename = "netguard_security_events.csv"

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "text/csv; charset=utf-8"
        }
    )


@app.route("/api/export/pdf")
@app.route("/api/export/pdf/<export_type>")
def export_pdf(export_type=None):
    """
    Generate and stream high-resolution, vector PDF reports (Device Inventory, Events, or Full Dossier).
    """
    from datetime import datetime
    target = export_type or request.args.get("type", "dossier")
    now_tag = datetime.now().strftime("%Y%m%d_%H%M%S")

    if target == "devices":
        devices_list = get_devices()
        pdf_bytes = generate_devices_pdf(devices_list)
        filename = f"netguard_device_inventory_{now_tag}.pdf"
    elif target == "events":
        events_list = get_events()
        pdf_bytes = generate_events_pdf(events_list)
        filename = f"netguard_security_events_{now_tag}.pdf"
    else:  # dossier or full audit report
        devices_list = get_devices()
        events_list = get_events()
        stats_data = get_stats()
        pdf_bytes = generate_dossier_pdf(stats_data, devices_list, events_list)
        filename = f"netguard_secops_dossier_{now_tag}.pdf"

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Content-Type": "application/pdf"
        }
    )


# Fallback for templates/static if referenced directly
@app.route("/templates/static/<path:filename>")
def templates_static(filename):
    return send_from_directory(STATIC_DIR, filename)


def get_lan_ip():
    """Detect the active host IP address on the local network."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


if __name__ == "__main__":
    lan_ip = get_lan_ip()
    port = int(os.environ.get("PORT", 5000))
    print("=" * 68)
    print("  NETGUARD — NETWORK SECURITY & ARP THREAT DETECTION SYSTEM")
    print("=" * 68)
    print(f"  [+] Local Interface:    http://127.0.0.1:{port}")
    print(f"  [+] Network Subnet:     http://{lan_ip}:{port}")
    print(f"  [+] Passive Sniffer:    Promiscuous Mode Layer-2 Ready")
    print("=" * 68)
    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        use_reloader=False
    )
