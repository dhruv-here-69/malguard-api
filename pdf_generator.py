import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable
)


def safe(value, default="N/A"):
    if value is None or value == "":
        return default
    return str(value)


def list_text(items):
    if not items:
        return ["insufficient evidence"]
    if isinstance(items, list):
        return items
    return [str(items)]


def join_items(items):
    return ", ".join(list_text(items))


def bool_badge(value):
    if value is True:
        return "DETECTED"
    if value is False:
        return "NOT DETECTED"
    return "N/A"


def yes_no(value):
    if value is True:
        return "YES"
    if value is False:
        return "NO"
    return "N/A"


def severity_color(level):
    level = safe(level).lower()

    if level == "critical":
        return colors.HexColor("#7f1d1d")
    if level == "high":
        return colors.HexColor("#dc2626")
    if level == "medium":
        return colors.HexColor("#f59e0b")
    if level == "low":
        return colors.HexColor("#16a34a")

    return colors.HexColor("#374151")


def final_action_text(level):
    level = safe(level).lower()

    if level == "critical":
        return "IMMEDIATE ACTION REQUIRED"
    if level == "high":
        return "BLOCK AND INVESTIGATE"
    if level == "medium":
        return "REVIEW AND MONITOR"
    if level == "low":
        return "MONITOR / ALLOW IF TRUSTED"

    return "ANALYST REVIEW REQUIRED"


def make_para(value, style):
    return Paragraph(
        safe(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
        style
    )


def build_table(data, col_widths=None, header=True, cell_style=None):
    if cell_style is None:
        styles = getSampleStyleSheet()
        cell_style = ParagraphStyle(
            "CellStyle",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=11,
            wordWrap="CJK"
        )

    wrapped_data = []

    for row in data:
        wrapped_row = []

        for cell in row:
            wrapped_row.append(
                make_para(cell, cell_style)
            )

        wrapped_data.append(wrapped_row)

    table = Table(
        wrapped_data,
        colWidths=col_widths or [150, 330],
        repeatRows=1 if header else 0
    )

    table_styles = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#111827")),
    ]

    if header:
        table_styles += [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]
    else:
        table_styles += [
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e5e7eb")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ]

    table.setStyle(TableStyle(table_styles))
    return table


def paragraph_list(title, items, elements, heading_style, normal_style):
    elements.append(
        Paragraph(
            title,
            heading_style
        )
    )

    for item in list_text(items):
        elements.append(
            Paragraph(
                f"• {safe(item)}",
                normal_style
            )
        )


def get_domain_from_indicators(indicators):
    urls = list_text(indicators.get("urls"))

    if not urls or urls[0] == "insufficient evidence":
        return "N/A"

    try:
        parsed = urlparse(urls[0])

        if parsed.netloc:
            return parsed.netloc

        parsed = urlparse("https://" + urls[0])
        return parsed.netloc or "N/A"

    except Exception:
        return "N/A"


def get_first_url(indicators):
    urls = list_text(indicators.get("urls"))

    if not urls or urls[0] == "insufficient evidence":
        return "N/A"

    return ", ".join(urls)


def create_risk_meter(score_num, threat_level, normal_style):
    score_num = max(0, min(score_num, 100))

    total_width = 440
    filled_width = int((score_num / 100) * total_width)
    empty_width = total_width - filled_width

    if filled_width < 1:
        filled_width = 1

    if empty_width < 1:
        empty_width = 1

    color = severity_color(threat_level)

    score_label = Paragraph(
        f"<b>Risk Score:</b> {score_num}/100",
        normal_style
    )

    bar = Table(
        [["", ""]],
        colWidths=[filled_width, empty_width],
        rowHeights=[12]
    )

    bar.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, 0), color),
            ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#e5e7eb")),
            ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#cbd5e1")),
            ("PADDING", (0, 0), (-1, -1), 0),
        ])
    )

    scale = Table(
        [["0", "25", "50", "75", "100"]],
        colWidths=[88, 88, 88, 88, 88]
    )

    scale.setStyle(
        TableStyle([
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#475569")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 2),
        ])
    )

    meter = Table(
        [
            [score_label],
            [bar],
            [scale]
        ],
        colWidths=[460]
    )

    meter.setStyle(
        TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ])
    )

    return meter


def generate_pdf_report(data):
    temp = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".pdf"
    )

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
        textColor=colors.HexColor("#0f172a"),
        fontSize=24,
        leading=28,
        spaceAfter=6
    )

    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["BodyText"],
        textColor=colors.HexColor("#475569"),
        fontSize=10,
        leading=14,
        alignment=1
    )

    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#0f172a"),
        fontSize=15,
        leading=18,
        spaceBefore=14,
        spaceAfter=8
    )

    normal_style = ParagraphStyle(
        "NormalStyle",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#111827"),
        wordWrap="CJK"
    )

    small_style = ParagraphStyle(
        "SmallStyle",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#64748b")
    )

    elements = []

    scan_type = safe(data.get("scan_type"))
    threat_level = safe(data.get("threat_level"))
    category = safe(data.get("malware_category"))
    confidence = safe(data.get("confidence_score"))
    risk_score = safe(data.get("risk_score"))

    indicators = data.get("indicators", {})
    intel = data.get("url_intelligence", {})
    file_info = data.get("file_intelligence", {})

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report_id = f"MG-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    elements.append(
        Paragraph(
            "MalGuard AI Security Analysis Report",
            title_style
        )
    )

    elements.append(
        Paragraph(
            "Generative AI Powered Malware, URL, and Threat Intelligence Platform",
            subtitle_style
        )
    )

    elements.append(Spacer(1, 10))
    elements.append(
        HRFlowable(
            width="100%",
            thickness=1,
            color=colors.HexColor("#cbd5e1")
        )
    )
    elements.append(Spacer(1, 12))

    banner_data = [
        [
            Paragraph(
                f"<b>THREAT LEVEL</b><br/><font size='18'>{threat_level.upper()}</font>",
                normal_style
            ),
            Paragraph(
                f"<b>RISK SCORE</b><br/><font size='18'>{risk_score}/100</font>",
                normal_style
            ),
            Paragraph(
                f"<b>CONFIDENCE</b><br/><font size='18'>{confidence}%</font>",
                normal_style
            )
        ]
    ]

    banner = Table(
        banner_data,
        colWidths=[160, 160, 160]
    )

    sev_color = severity_color(threat_level)

    banner.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("PADDING", (0, 0), (-1, -1), 12),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BOX", (0, 0), (-1, -1), 1, sev_color),
        ])
    )

    elements.append(banner)
    elements.append(Spacer(1, 14))

    metadata = [
        ["Field", "Value"],
        ["Report ID", report_id],
        ["Generated At", now],
        ["Classification", "Security Internal"],
        ["Report Type", "Automated Threat Intelligence Report"],
        ["Scan Type", scan_type],
        ["Category", category],
        ["Engine", "MalGuard AI Threat Intelligence Engine v1"]
    ]

    elements.append(Paragraph("Report Metadata", heading_style))
    elements.append(build_table(metadata, [150, 330], header=True))

    elements.append(Paragraph("Scan Target", heading_style))

    if scan_type.lower() == "url":
        target_data = [
            ["Field", "Value"],
            ["Target Type", "URL"],
            ["Scanned URL", get_first_url(indicators)],
            ["Domain / Host", get_domain_from_indicators(indicators)],
            ["Analysis Mode", "URL reputation, WHOIS, page-content and threat-feed analysis"]
        ]

    else:
        target_data = [
            ["Field", "Value"],
            ["Target Type", "File"],
            ["Filename", safe(file_info.get("filename"), "N/A")],
            ["File Type", safe(file_info.get("file_type"), scan_type)],
            ["SHA256", safe(file_info.get("sha256"), "N/A")],
            ["Analysis Mode", "Static analysis, YARA detection, sandbox heuristics and AI assessment"]
        ]

    elements.append(build_table(target_data, [150, 330], header=True))

    elements.append(Paragraph("Analyst Verdict", heading_style))

    verdict = (
        f"This scan was classified as <b>{threat_level}</b> with a risk score of "
        f"<b>{risk_score}/100</b>. The assigned category is <b>{category}</b>. "
        f"The verdict is based on deterministic backend scoring, threat intelligence, "
        f"and AI-assisted SOC analysis."
    )

    elements.append(
        Paragraph(
            verdict,
            normal_style
        )
    )

    summary_data = [
        ["Scan Type", scan_type],
        ["Threat Level", threat_level],
        ["Threat Category", category],
        ["Confidence Score", f"{confidence}%"],
        ["Risk Score", f"{risk_score}/100"]
    ]

    elements.append(Paragraph("Executive Summary", heading_style))
    elements.append(build_table(summary_data, [160, 320], header=False))

    paragraph_list(
        "Key Findings",
        data.get("key_findings"),
        elements,
        heading_style,
        normal_style
    )

    paragraph_list(
        "Attack Vectors",
        data.get("attack_vectors"),
        elements,
        heading_style,
        normal_style
    )

    ioc_data = [
        ["Indicator Type", "Values"],
        ["Permissions", join_items(indicators.get("permissions"))],
        ["DLL Imports", join_items(indicators.get("dll_imports"))],
        ["API Calls", join_items(indicators.get("api_calls"))],
        ["YARA Matches", join_items(indicators.get("yara_matches"))],
        ["URLs", join_items(indicators.get("urls"))]
    ]

    elements.append(Paragraph("Indicators of Compromise", heading_style))
    elements.append(build_table(ioc_data, [130, 350], header=True))

    if scan_type.lower() == "file":
        file_intel_data = [
            ["Signal", "Value"],
            ["Filename", safe(file_info.get("filename"), "N/A")],
            ["File Type", safe(file_info.get("file_type"), "N/A")],
            ["SHA256", safe(file_info.get("sha256"), "N/A")],
            ["YARA Matches", join_items(indicators.get("yara_matches"))],
            ["Suspicious DLL Imports", join_items(indicators.get("dll_imports"))],
            ["Suspicious API Calls", join_items(indicators.get("api_calls"))],
            ["Sandbox Executed", yes_no(file_info.get("sandbox_executed"))],
            ["Sandbox Network Activity", yes_no(file_info.get("sandbox_network_activity"))],
            ["Sandbox Process Spawned", yes_no(file_info.get("sandbox_process_spawned"))],
            ["Sandbox File Changes", join_items(file_info.get("sandbox_file_changes"))]
        ]

        elements.append(Paragraph("File Intelligence", heading_style))
        elements.append(build_table(file_intel_data, [160, 320], header=True))

        sources = [
            ["Detection Source", "Result"],
            [
                "YARA Engine",
                "DETECTED" if indicators.get("yara_matches") and indicators.get("yara_matches") != ["insufficient evidence"] else "NOT DETECTED"
            ],
            [
                "Static Import Analysis",
                "DETECTED" if indicators.get("api_calls") and indicators.get("api_calls") != ["insufficient evidence"] else "NO STRONG SIGNALS"
            ],
            ["Sandbox Heuristics", "ACTIVE"],
            ["MalGuard AI Engine", "ACTIVE"]
        ]

        elements.append(Paragraph("File Detection Sources", heading_style))
        elements.append(build_table(sources, [220, 260], header=True))

    if scan_type.lower() == "url":
        intel_data = [
            ["Signal", "Value"],
            ["Google Safe Browsing", bool_badge(intel.get("google_safe_browsing"))],
            ["OpenPhish", bool_badge(intel.get("openphish_hit"))],
            ["Domain Age", f"{safe(intel.get('domain_age_days'))} days"],
            ["Creation Date", safe(intel.get("creation_date"), "unavailable")],
            ["Page Content Score", safe(intel.get("page_content_score"))],
            ["Redirect Count", safe(intel.get("redirect_count"))],
            ["HTTP Status", safe(intel.get("http_status"))],
            ["Page Signals", join_items(intel.get("page_signals"))]
        ]

        elements.append(Paragraph("URL Threat Intelligence", heading_style))
        elements.append(build_table(intel_data, [170, 310], header=True))

        sources = [
            ["Detection Source", "Result"],
            ["Google Safe Browsing", "DETECTED" if intel.get("google_safe_browsing") else "NOT DETECTED"],
            ["OpenPhish", "DETECTED" if intel.get("openphish_hit") else "NOT DETECTED"],
            ["Page Content Analysis", "DETECTED" if int(intel.get("page_content_score") or 0) > 0 else "NO SIGNALS"],
            ["WHOIS Intelligence", "AVAILABLE" if int(intel.get("domain_age_days") or 0) > 0 else "UNAVAILABLE"],
            ["MalGuard AI Engine", "ACTIVE"]
        ]

        elements.append(Paragraph("Threat Intelligence Sources", heading_style))
        elements.append(build_table(sources, [220, 260], header=True))

    try:
        score_num = int(float(risk_score))
    except Exception:
        score_num = 0

    elements.append(Paragraph("Risk Visualization", heading_style))
    elements.append(create_risk_meter(score_num, threat_level, normal_style))

    elements.append(Paragraph("Technical Analysis", heading_style))
    elements.append(
        Paragraph(
            safe(data.get("explanation")),
            normal_style
        )
    )

    elements.append(Paragraph("Final Analyst Recommendation", heading_style))

    recommendation_banner = Table(
        [[
            Paragraph(
                f"<b>{final_action_text(threat_level)}</b><br/>Threat Level: {threat_level} | Risk Score: {risk_score}/100",
                normal_style
            )
        ]],
        colWidths=[480]
    )

    recommendation_banner.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), severity_color(threat_level)),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("PADDING", (0, 0), (-1, -1), 14),
        ])
    )

    elements.append(recommendation_banner)

    elements.append(Paragraph("Recommended Action", heading_style))
    elements.append(
        Paragraph(
            safe(data.get("recommended_action")),
            normal_style
        )
    )

    paragraph_list(
        "MITRE ATT&CK Mapping",
        data.get("mitre_attack"),
        elements,
        heading_style,
        normal_style
    )

    elements.append(Spacer(1, 20))

    elements.append(
        HRFlowable(
            width="100%",
            thickness=0.5,
            color=colors.HexColor("#cbd5e1")
        )
    )

    elements.append(Spacer(1, 8))

    elements.append(
        Paragraph(
            "MalGuard AI Threat Intelligence Platform",
            small_style
        )
    )

    elements.append(
        Paragraph(
            f"Report ID: {report_id} • Generated: {now}",
            small_style
        )
    )

    elements.append(
        Paragraph(
            "This report is intended for security analysis and incident response support.",
            small_style
        )
    )

    doc.build(elements)

    return temp.name
