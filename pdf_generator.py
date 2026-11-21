"""
NETGUARD — Network Security & ARP Threat Detection System
Automated Enterprise PDF Report Generator (ReportLab Engine)
Produces high-resolution, government/audit-ready PDF dossiers.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


# Color Palette (Matching NETGUARD Metallic Silver Industrial Theme)
GRAPHITE = colors.HexColor("#252B32")
STEEL_DARK = colors.HexColor("#3D444D")
STEEL_GRAY = colors.HexColor("#8C949D")
LIGHT_SILVER = colors.HexColor("#E2E5E8")
ROW_BG_LIGHT = colors.HexColor("#F6F8FA")
WHITE = colors.HexColor("#FFFFFF")
CRIMSON = colors.HexColor("#DC2626")
AMBER = colors.HexColor("#D97706")
EMERALD = colors.HexColor("#059669")
BLUE_ACCENT = colors.HexColor("#2563EB")


def _get_styles():
    """Build typographic hierarchy for PDF generation."""
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=GRAPHITE,
        alignment=TA_LEFT
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=STEEL_GRAY,
        alignment=TA_LEFT
    )

    meta_key_style = ParagraphStyle(
        'MetaKey',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=STEEL_DARK
    )

    meta_val_style = ParagraphStyle(
        'MetaVal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=GRAPHITE
    )

    th_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=WHITE,
        alignment=TA_LEFT
    )

    td_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=GRAPHITE,
        alignment=TA_LEFT
    )

    td_mono = ParagraphStyle(
        'TableCellMono',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=GRAPHITE,
        alignment=TA_LEFT
    )

    footer_style = ParagraphStyle(
        'FooterNotice',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=7.5,
        leading=10,
        textColor=STEEL_GRAY,
        alignment=TA_CENTER
    )

    return {
        "title": title_style,
        "subtitle": subtitle_style,
        "meta_key": meta_key_style,
        "meta_val": meta_val_style,
        "th": th_style,
        "td": td_style,
        "td_mono": td_mono,
        "footer": footer_style
    }


def generate_devices_pdf(devices_list):
    """
    Generate clean, landscape PDF report of all discovered network devices.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = _get_styles()
    story = []

    # Title & Header
    story.append(Paragraph("NETGUARD — Network Security & ARP Threat Detection", styles['title']))
    story.append(Paragraph("OFFICIAL PHYSICAL DEVICE INVENTORY AUDIT REPORT", styles['subtitle']))
    story.append(Spacer(1, 10))

    # Metadata Grid
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    meta_data = [
        [
            Paragraph("Report Type:", styles['meta_key']), Paragraph("Hardware Subnet Device Inventory", styles['meta_val']),
            Paragraph("Generated Timestamp:", styles['meta_key']), Paragraph(now_str, styles['meta_val'])
        ],
        [
            Paragraph("Total Devices Discovered:", styles['meta_key']), Paragraph(f"{len(devices_list)} Hardware Nodes", styles['meta_val']),
            Paragraph("Classification Level:", styles['meta_key']), Paragraph("DEFENSE / GOVERNMENT COMPLIANCE", styles['meta_val'])
        ]
    ]
    meta_table = Table(meta_data, colWidths=[130, 230, 130, 250])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=STEEL_GRAY, spaceAfter=12))

    # Table Header
    headers = ["#", "IP Address", "MAC Address", "Hostname / Role", "Hardware Vendor", "First Seen", "Last Seen", "Observations", "Status"]
    table_data = [[Paragraph(h, styles['th']) for h in headers]]

    for idx, d in enumerate(devices_list, start=1):
        status_val = d.get('status', 'Active')
        status_color = "#DC2626" if status_val == "Suspicious" else "#059669"
        status_p = Paragraph(f"<font color='{status_color}'><b>{status_val}</b></font>", styles['td'])

        row = [
            Paragraph(str(idx), styles['td_mono']),
            Paragraph(d.get('ip', '-'), styles['td_mono']),
            Paragraph(d.get('mac', '-'), styles['td_mono']),
            Paragraph(d.get('hostname', '-') or 'network-host.lan', styles['td']),
            Paragraph(d.get('vendor', '-') or 'Network Host NIC', styles['td']),
            Paragraph(d.get('first_seen', '-'), styles['td']),
            Paragraph(d.get('last_seen', '-'), styles['td']),
            Paragraph(str(d.get('observations', 1)), styles['td_mono']),
            status_p
        ]
        table_data.append(row)

    col_widths = [25, 80, 105, 130, 140, 95, 95, 45, 55]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), GRAPHITE),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, ROW_BG_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.5, STEEL_GRAY),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("NETGUARD Sensor Baseline &bull; Cryptographically Verified Forensic Record &bull; Confidential", styles['footer']))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def generate_events_pdf(events_list):
    """
    Generate clean landscape PDF log of all security events and ARP mapping discrepancies.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = _get_styles()
    story = []

    # Title & Header
    story.append(Paragraph("NETGUARD — Network Security & ARP Threat Detection", styles['title']))
    story.append(Paragraph("INCIDENT RESPONSE & SECURITY EVENTS AUDIT LOG", styles['subtitle']))
    story.append(Spacer(1, 10))

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    high_count = sum(1 for e in events_list if e.get('severity') == 'HIGH')
    meta_data = [
        [
            Paragraph("Report Scope:", styles['meta_key']), Paragraph("Forensic Event Log & ARP Threat Telemetry", styles['meta_val']),
            Paragraph("Generated Timestamp:", styles['meta_key']), Paragraph(now_str, styles['meta_val'])
        ],
        [
            Paragraph("Total Logged Events:", styles['meta_key']), Paragraph(f"{len(events_list)} Recorded Incidents", styles['meta_val']),
            Paragraph("Critical Alerts (High Severity):", styles['meta_key']), Paragraph(f"<font color='#DC2626'><b>{high_count} Incidents</b></font>", styles['meta_val'])
        ]
    ]
    meta_table = Table(meta_data, colWidths=[140, 220, 140, 240])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))
    story.append(HRFlowable(width="100%", thickness=1, color=STEEL_GRAY, spaceAfter=12))

    headers = ["ID", "Timestamp", "Event Type", "Severity", "Target IP", "Previous MAC", "Observed MAC", "Description", "Status"]
    table_data = [[Paragraph(h, styles['th']) for h in headers]]

    for e in events_list:
        sev = e.get('severity', 'INFO')
        if sev == 'HIGH':
            sev_color = "#DC2626"
        elif sev == 'MEDIUM':
            sev_color = "#D97706"
        else:
            sev_color = "#3D444D"
        sev_p = Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", styles['td'])

        row = [
            Paragraph(f"#{e.get('id', '-')}", styles['td_mono']),
            Paragraph(e.get('timestamp', '-'), styles['td_mono']),
            Paragraph(e.get('type', '-'), styles['td_mono']),
            sev_p,
            Paragraph(e.get('ip', '-'), styles['td_mono']),
            Paragraph(e.get('previous_mac', '-') or '-', styles['td_mono']),
            Paragraph(e.get('mac', '-') or '-', styles['td_mono']),
            Paragraph(e.get('description', '-'), styles['td']),
            Paragraph(e.get('investigation_status', 'Pending Review'), styles['td'])
        ]
        table_data.append(row)

    col_widths = [35, 95, 95, 45, 80, 95, 95, 160, 70]
    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), GRAPHITE),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, ROW_BG_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.5, STEEL_GRAY),
    ]))
    story.append(table)
    story.append(Spacer(1, 20))

    story.append(Paragraph("NETGUARD Security Operations Center &bull; Automated Intrusion Detection Record &bull; Official Dossier", styles['footer']))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


def generate_dossier_pdf(stats, devices_list, events_list, monitor_info=None):
    """
    Generate comprehensive, multi-section executive cybersecurity dossier.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = _get_styles()
    story = []

    # Title
    story.append(Paragraph("NETGUARD — Network Security & ARP Threat Detection", styles['title']))
    story.append(Paragraph("COMPREHENSIVE FORENSIC AUDIT & DEFENSE EVALUATION DOSSIER", styles['subtitle']))
    story.append(Spacer(1, 10))

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    secops_station = "172.100.4.219 (Aswanth-PC)"
    gateway = "172.100.0.1 (Ruijie Networks)"

    # Executive Summary Card
    card_data = [
        [
            Paragraph("<b>Total Devices</b>", styles['th']),
            Paragraph("<b>Total Events</b>", styles['th']),
            Paragraph("<b>Anomalies</b>", styles['th']),
            Paragraph("<b>Capture Engine</b>", styles['th'])
        ],
        [
            Paragraph(f"<font size=13><b>{stats.get('devices', len(devices_list))}</b></font><br/>Active Subnet Nodes", styles['td']),
            Paragraph(f"<font size=13><b>{stats.get('events', len(events_list))}</b></font><br/>Incident Trail", styles['td']),
            Paragraph(f"<font size=13 color='#DC2626'><b>{stats.get('mapping_changes', 0)}</b></font><br/>Mapping Conflicts", styles['td']),
            Paragraph(f"<font size=13 color='#059669'><b>ONLINE</b></font><br/>Scapy Promiscuous Sniffer", styles['td'])
        ]
    ]
    card_table = Table(card_data, colWidths=[135, 135, 135, 135])
    card_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), GRAPHITE),
        ('BACKGROUND', (0, 1), (-1, 1), ROW_BG_LIGHT),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 1, STEEL_GRAY),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(card_table)
    story.append(Spacer(1, 14))

    # System Telemetry & Metadata
    meta_data = [
        [
            Paragraph("<b>Host SecOps Station:</b>", styles['meta_key']), Paragraph(secops_station, styles['meta_val']),
            Paragraph("<b>Report Generated:</b>", styles['meta_key']), Paragraph(now_str, styles['meta_val'])
        ],
        [
            Paragraph("<b>Default Gateway:</b>", styles['meta_key']), Paragraph(gateway, styles['meta_val']),
            Paragraph("<b>Compliance Standard:</b>", styles['meta_key']), Paragraph("NIST SP 800-94 / ISO 27001", styles['meta_val'])
        ]
    ]
    meta_table = Table(meta_data, colWidths=[120, 150, 130, 140])
    meta_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1, color=STEEL_GRAY, spaceAfter=10))

    # Section 1: Discovered Devices (Top 10 summary)
    story.append(Paragraph("<b>SECTION 1: SUB-NETWORK DEVICE INVENTORY (SAMPLE)</b>", styles['meta_key']))
    story.append(Spacer(1, 4))
    dev_headers = ["IP Address", "MAC Address", "Hardware Vendor", "Observations", "Status"]
    dev_table_data = [[Paragraph(h, styles['th']) for h in dev_headers]]

    for d in devices_list[:12]:
        status_val = d.get('status', 'Active')
        status_color = "#DC2626" if status_val == "Suspicious" else "#059669"
        dev_table_data.append([
            Paragraph(d.get('ip', '-'), styles['td_mono']),
            Paragraph(d.get('mac', '-'), styles['td_mono']),
            Paragraph(d.get('vendor', '-') or 'Network Host', styles['td']),
            Paragraph(str(d.get('observations', 1)), styles['td_mono']),
            Paragraph(f"<font color='{status_color}'><b>{status_val}</b></font>", styles['td'])
        ])

    dev_table = Table(dev_table_data, colWidths=[100, 120, 170, 70, 80], repeatRows=1)
    dev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), STEEL_DARK),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, ROW_BG_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.5, STEEL_GRAY),
    ]))
    story.append(dev_table)
    story.append(Spacer(1, 14))

    # Section 2: Recent Security Events
    story.append(Paragraph("<b>SECTION 2: SECURITY EVENT AUDIT RECORD & ARP TELEMETRY</b>", styles['meta_key']))
    story.append(Spacer(1, 4))
    ev_headers = ["ID", "Timestamp", "Type", "Severity", "Target IP", "Description"]
    ev_table_data = [[Paragraph(h, styles['th']) for h in ev_headers]]

    for e in events_list[:10]:
        sev = e.get('severity', 'INFO')
        sev_color = "#DC2626" if sev == "HIGH" else ("#D97706" if sev == "MEDIUM" else "#3D444D")
        ev_table_data.append([
            Paragraph(f"#{e.get('id', '-')}", styles['td_mono']),
            Paragraph(e.get('timestamp', '-'), styles['td_mono']),
            Paragraph(e.get('type', '-'), styles['td_mono']),
            Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", styles['td']),
            Paragraph(e.get('ip', '-'), styles['td_mono']),
            Paragraph(e.get('description', '-'), styles['td'])
        ])

    ev_table = Table(ev_table_data, colWidths=[30, 95, 95, 50, 80, 190], repeatRows=1)
    ev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), STEEL_DARK),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, ROW_BG_LIGHT]),
        ('GRID', (0, 0), (-1, -1), 0.5, STEEL_GRAY),
    ]))
    story.append(ev_table)
    story.append(Spacer(1, 18))

    # Compliance & Signature Box
    sig_data = [
        [
            Paragraph("<b>Lead Security Analyst Signature:</b><br/><br/>_____________________________________<br/>Aswanth Kumar / SecOps Lead", styles['td']),
            Paragraph("<b>Evaluation / Review Authority:</b><br/><br/>_____________________________________<br/>Government / Academic Committee Examiner", styles['td'])
        ]
    ]
    sig_table = Table(sig_data, colWidths=[270, 270])
    sig_table.setStyle(TableStyle([
        ('BOX', (0, 0), (-1, -1), 1, STEEL_GRAY),
        ('BACKGROUND', (0, 0), (-1, -1), ROW_BG_LIGHT),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(KeepTogether(sig_table))

    story.append(Spacer(1, 12))
    story.append(Paragraph("NETGUARD Network Defense Sensor &bull; Official Evaluation Dossier &bull; Page 1 of 1", styles['footer']))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
