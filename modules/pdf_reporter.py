import os
import re
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

def clean_markdown_for_pdf(text):
    """Converts Markdown syntax to ReportLab compatible HTML tags."""
    if not text:
        return ""
    # Convert Headers
    text = re.sub(r'### (.*?)\n', r'<br/><b><font color="#2e75b6">\1</font></b><br/>', text)
    text = re.sub(r'## (.*?)\n', r'<br/><b><font color="#1f4e79">\1</font></b><br/>', text)
    # Convert Bold
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    # Convert Newlines
    text = text.replace('\n', '<br/>')
    # Remove raw backticks
    text = text.replace('```bash', '').replace('```', '')
    return text

def generate_pdf(results, target, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace("/", "_").replace(":", "_")
    filename = f"{output_dir}/report_{safe_target}_{ts}.pdf"

    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    # --- Custom Styles ---
    title_style = ParagraphStyle(
        'CustomTitle', parent=styles['Heading1'],
        alignment=TA_CENTER, textColor=colors.HexColor("#1f4e79"), fontSize=24, spaceAfter=20
    )
    h2_style = ParagraphStyle(
        'CustomH2', parent=styles['Heading2'],
        textColor=colors.HexColor("#2e75b6"), spaceBefore=15, spaceAfter=10
    )
    normal_style = styles['Normal']

    # --- Title & Meta ---
    elements.append(Paragraph("🛡️ Security Assessment Report", title_style))
    elements.append(Paragraph(f"<b>Target:</b> {target}", normal_style))
    elements.append(Paragraph(f"<b>Date:</b> {ts}", normal_style))
    elements.append(Spacer(1, 15))

    nmap = results.get("nmap", {})
    msf = results.get("msf", {})

    # --- Executive Summary Table ---
    elements.append(Paragraph("📊 Executive Summary", h2_style))
    summary_data = [
        ["Metric", "Count"],
        ["Hosts Discovered", str(len(nmap.get("hosts", [])))],
        ["Open Ports", str(len(nmap.get("open_ports", [])))],
        ["HTTP Services", str(len(nmap.get("http_services", [])))],
        ["Exploit Candidates", str(msf.get("count", 0))]
    ]
    summary_table = Table(summary_data, colWidths=[200, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1f4e79")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f2f2f2")),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 15))

    # --- Open Ports Table ---
    elements.append(Paragraph("🔍 Open Ports", h2_style))
    port_data = [["Host", "Port", "Service"]]
    for p in nmap.get("open_ports", [])[:15]:
        port_data.append([p.get("host", ""), str(p.get("port", "")), p.get("service", "")])
    
    if len(port_data) > 1:
        port_table = Table(port_data, colWidths=[120, 80, 100])
        port_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2e75b6")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        elements.append(port_table)
    else:
        elements.append(Paragraph("No open ports found.", normal_style))
    elements.append(Spacer(1, 15))

    # --- AI Threat Analysis & Remediation ---
    if "ai_threat_analysis" in results:
        elements.append(Paragraph("🧠 AI Threat Analysis", h2_style))
        ai_text = clean_markdown_for_pdf(results["ai_threat_analysis"])
        elements.append(Paragraph(ai_text, normal_style))
        elements.append(Spacer(1, 10))

    if "remediation_plan" in results:
        elements.append(Paragraph("🛠️ Automated Remediation Plan", h2_style))
        rem_text = clean_markdown_for_pdf(results["remediation_plan"])
        elements.append(Paragraph(rem_text, normal_style))

    # --- Build PDF ---
    doc.build(elements)
    print(f"[✓] PDF Report saved: {filename}")
    return filename
