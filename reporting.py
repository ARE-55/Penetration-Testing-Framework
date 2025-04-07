import json
import os
from datetime import datetime
from reportlab.lib.pagesizes import LETTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def extract_key_info(scan_results):
    """Extract relevant information from scan results."""
    summary = {
        "Target": scan_results.get("target", "N/A"),
        "Vulnerabilities": [],
        "Data Dump": []
    }
    
    sqlmap_output = scan_results.get("sqlmap_results", "")
    
    if "Payload" in sqlmap_output:
        vulnerabilities = []
        for line in sqlmap_output.splitlines():
            if "Payload:" in line:
                vulnerabilities.append(line.strip())
        summary["Vulnerabilities"].extend(vulnerabilities)
    
    if "Database:" in sqlmap_output:
        db_lines = [line.strip() for line in sqlmap_output.splitlines() if "Database:" in line or "Table:" in line or "entries" in line]
        summary["Data Dump"].extend(db_lines)

    return summary

def generate_json_report(scan_results, filename="scan_report.json"):
    """Generate a JSON report for the scan results."""
    print(f"\n[+] Generating JSON report: {filename}...")
    report_data = {
        "report_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_summary": extract_key_info(scan_results)
    }

    with open(filename, "w") as json_file:
        json.dump(report_data, json_file, indent=4)

    print(f"[+] JSON report saved as {filename}.")

def generate_html_report(scan_results, filename="scan_report.html"):
    """Generate a clean HTML report."""
    print(f"\n[+] Generating HTML report: {filename}...")

    summary = extract_key_info(scan_results)

    html_content = f"""
    <html>
    <head>
        <title>Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
            h1, h2 {{ color: #333; }}
            .vuln {{ color: red; }}
            .data {{ color: green; }}
            .section {{ margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <h1>Scan Report</h1>
        <p><strong>Report Generated on:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <div class="section">
            <h2>Target</h2>
            <p>{summary["Target"]}</p>
        </div>
        <div class="section">
            <h2 class="vuln">Vulnerabilities</h2>
            <ul>
                {''.join(f'<li>{v}</li>' for v in summary["Vulnerabilities"])}
            </ul>
        </div>
        <div class="section">
            <h2 class="data">Data Dump</h2>
            <ul>
                {''.join(f'<li>{d}</li>' for d in summary["Data Dump"])}
            </ul>
        </div>
    </body>
    </html>
    """

    with open(filename, "w") as html_file:
        html_file.write(html_content)

    print(f"[+] HTML report saved as {filename}.")

def generate_pdf_report(scan_results, filename="scan_report.pdf"):
    """Generate a PDF report using reportlab."""
    print(f"\n[+] Generating PDF report: {filename}...")

    summary = extract_key_info(scan_results)

    doc = SimpleDocTemplate(filename, pagesize=LETTER)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("Scan Report", styles['Title']))
    content.append(Spacer(1, 12))
    content.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    content.append(Spacer(1, 12))
    content.append(Paragraph(f"Target: {summary['Target']}", styles['Normal']))
    content.append(Spacer(1, 12))
    
    # Vulnerabilities
    content.append(Paragraph("Vulnerabilities:", styles['Heading2']))
    if summary['Vulnerabilities']:
        vuln_data = [[v] for v in summary['Vulnerabilities']]
        vuln_table = Table(vuln_data, colWidths=[500])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        content.append(vuln_table)
    else:
        content.append(Paragraph("No vulnerabilities found.", styles['Normal']))
    
    content.append(Spacer(1, 12))
    
    # Data Dump
    content.append(Paragraph("Data Dump:", styles['Heading2']))
    if summary['Data Dump']:
        data_dump = [[d] for d in summary['Data Dump']]
        dump_table = Table(data_dump, colWidths=[500])
        dump_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        content.append(dump_table)
    else:
        content.append(Paragraph("No data dump found.", styles['Normal']))

    doc.build(content)
    print(f"[+] PDF report saved as {filename}.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan_results = json.loads(sys.argv[1])
        generate_json_report(scan_results)
        generate_html_report(scan_results)
        generate_pdf_report(scan_results)
    else:
        print("[!] No scan results provided.")
