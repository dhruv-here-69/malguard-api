import tempfile
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


def safe(value, default="N/A"):
    if value is None or value == "":
        return default
    return str(value)


def list_text(items):
    if not items:
        return ["insufficient evidence"]
    return items


def generate_pdf_report(data):
    temp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")

    doc = SimpleDocTemplate(
        temp.name,
        pagesize=A4,
        rightMargin=35,
        leftMargin=35,
        topMargin=35,
        bottomMargin=35
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        textColor=colors.HexColor("#111827"),
        fontSize=22,
        spaceAfter=16
    )

    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#1f2937"),
        fontSize=15,
        spaceBefore=12,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalStyle",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14
    )

    elements = []

    elements.append(
        Paragraph("MalGuard AI Security Analysis Report", title_style)
    )

    elements.append(
        Paragraph(
            "AI-powered malware, file, and URL threat intelligence report",
            normal_style
        )
    )

    elements.append(Spacer(1, 15))

    summary_data = [
        ["Scan Type", safe(data.get("scan_type"))],
        ["Threat Level", safe(data.get("threat_level"))],
        ["Category", safe(data.get("malware_category"))],
        ["Confidence Score", f"{safe(data.get('confidence_score'))}%"],
        ["Risk Score", f"{safe(data.get('risk_score'))}/100"]
    ]

    summary_table = Table(summary_data, colWidths=[150, 330])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e5e7eb")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 8),
    ]))

    elements.append(summary_table)

    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Key Findings", heading_style))
    for item in list_text(data.get("key_findings")):
        elements.append(Paragraph(f"• {safe(item)}", normal_style))

    elements.append(Paragraph("Attack Vectors", heading_style))
    for item in list_text(data.get("attack_vectors")):
        elements.append(Paragraph(f"• {safe(item)}", normal_style))

    indicators = data.get("indicators", {})

    elements.append(Paragraph("Indicators of Compromise", heading_style))

    ioc_data = [
        ["Indicator Type", "Values"],
        ["Permissions", ", ".join(list_text(indicators.get("permissions")))],
        ["DLL Imports", ", ".join(list_text(indicators.get("dll_imports")))],
        ["API Calls", ", ".join(list_text(indicators.get("api_calls")))],
        ["YARA Matches", ", ".join(list_text(indicators.get("yara_matches")))],
        ["URLs", ", ".join(list_text(indicators.get("urls")))]
    ]

    ioc_table = Table(ioc_data, colWidths=[140, 340])
    ioc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(ioc_table)

    if data.get("scan_type") == "url":
        intel = data.get("url_intelligence", {})

        elements.append(Paragraph("URL Intelligence", heading_style))

        intel_data = [
            ["Google Safe Browsing", safe(intel.get("google_safe_browsing"))],
            ["OpenPhish Hit", safe(intel.get("openphish_hit"))],
            ["Domain Age", f"{safe(intel.get('domain_age_days'))} days"],
            ["Creation Date", safe(intel.get("creation_date"))],
            ["Page Content Score", safe(intel.get("page_content_score"))],
            ["Redirect Count", safe(intel.get("redirect_count"))],
            ["HTTP Status", safe(intel.get("http_status"))],
            ["Page Signals", ", ".join(list_text(intel.get("page_signals")))]
        ]

        intel_table = Table(intel_data, colWidths=[160, 320])
        intel_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e5e7eb")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("PADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))

        elements.append(intel_table)

    elements.append(Paragraph("Technical Analysis", heading_style))
    elements.append(
        Paragraph(
            safe(data.get("explanation")),
            normal_style
        )
    )

    elements.append(Paragraph("Recommended Action", heading_style))
    elements.append(
        Paragraph(
            safe(data.get("recommended_action")),
            normal_style
        )
    )

    elements.append(Paragraph("MITRE ATT&CK Mapping", heading_style))
    for item in list_text(data.get("mitre_attack")):
        elements.append(Paragraph(f"• {safe(item)}", normal_style))

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "Generated by MalGuard AI",
            ParagraphStyle(
                "Footer",
                parent=styles["BodyText"],
                fontSize=8,
                textColor=colors.HexColor("#6b7280"),
                alignment=1
            )
        )
    )

    doc.build(elements)

    return temp.name
