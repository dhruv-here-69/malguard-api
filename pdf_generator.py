import tempfile
from datetime import datetime, timezone

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


def bool_badge(value):
    if value is True:
        return "DETECTED"

    if value is False:
        return "NOT DETECTED"

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


def build_table(data, col_widths=None, header=True):
    table = Table(
        data,
        colWidths=col_widths or [160, 320],
        repeatRows=1 if header else 0
    )

    table_styles = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("PADDING", (0, 0), (-1, -1), 7),
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
        textColor=colors.HexColor("#111827")
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

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report_id = f"MG-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    # ==========================
    # HEADER
    # ==========================

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

    # ==========================
    # SEVERITY BANNER
    # ==========================

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

    # ==========================
    # REPORT METADATA
    # ==========================

    metadata = [
        ["Field", "Value"],
        ["Report ID", report_id],
        ["Generated At", now],
        ["Scan Type", scan_type],
        ["Category", category],
        ["Engine", "MalGuard AI Threat Intelligence Engine v1"]
    ]

    elements.append(
        Paragraph(
            "Report Metadata",
            heading_style
        )
    )

    elements.append(
        build_table(
            metadata,
            [150, 330],
            header=True
        )
    )

    # ==========================
    # SCAN TARGET
    # ==========================

    elements.append(
        Paragraph(
            "Scan Target",
            heading_style
        )
    )

    if scan_type.lower() == "url":
        urls = list_text(indicators.get("urls"))

        target_data = [
            ["Field", "Value"],
            ["Target Type", "URL"],
            ["Scanned URL", ", ".join(urls)],
            ["Domain / Host", safe(data.get("domain"), "Provided in backend result")],
            ["Analysis Mode", "URL reputation, WHOIS, page-content and threat-feed analysis"]
        ]

    else:
        target_data = [
            ["Field", "Value"],
            ["Target Type", "File"],
            ["File Type", scan_type],
            ["Analysis Mode", "Static analysis, YARA detection, sandbox heuristics and AI assessment"]
        ]

    elements.append(
        build_table(
            target_data,
            [150, 330],
            header=True
        )
    )

    # ==========================
    # ANALYST VERDICT
    # ==========================

    elements.append(
        Paragraph(
            "Analyst Verdict",
            heading_style
        )
    )

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

    # ==========================
    # EXECUTIVE SUMMARY
    # ==========================

    summary_data = [
        ["Scan Type", scan_type],
        ["Threat Level", threat_level],
        ["Threat Category", category],
        ["Confidence Score", f"{confidence}%"],
        ["Risk Score", f"{risk_score}/100"]
    ]

    elements.append(
        Paragraph(
            "Executive Summary",
            heading_style
        )
    )

    elements.append(
        build_table(
            summary_data,
            [160, 320],
            header=False
        )
    )

    # ==========================
    # KEY FINDINGS
    # ==========================

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

    # ==========================
    # IOC TABLE
    # ==========================

    ioc_data = [
        ["Indicator Type", "Values"],
        ["Permissions", ", ".join(list_text(indicators.get("permissions")))],
        ["DLL Imports", ", ".join(list_text(indicators.get("dll_imports")))],
        ["API Calls", ", ".join(list_text(indicators.get("api_calls")))],
        ["YARA Matches", ", ".join(list_text(indicators.get("yara_matches")))],
        ["URLs", ", ".join(list_text(indicators.get("urls")))]
    ]

    elements.append(
        Paragraph(
            "Indicators of Compromise",
            heading_style
        )
    )

    elements.append(
        build_table(
            ioc_data,
            [140, 340],
            header=True
        )
    )

    # ==========================
    # URL INTELLIGENCE
    # ==========================

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
            ["Page Signals", ", ".join(list_text(intel.get("page_signals")))]
        ]

        elements.append(
            Paragraph(
                "URL Threat Intelligence",
                heading_style
            )
        )

        elements.append(
            build_table(
                intel_data,
                [170, 310],
                header=True
            )
        )

        # ==========================
        # THREAT INTELLIGENCE SOURCES
        # ==========================

        sources = [
            ["Detection Source", "Result"],
            [
                "Google Safe Browsing",
                "DETECTED" if intel.get("google_safe_browsing") else "NOT DETECTED"
            ],
            [
                "OpenPhish",
                "DETECTED" if intel.get("openphish_hit") else "NOT DETECTED"
            ],
            [
                "Page Content Analysis",
                "DETECTED" if int(intel.get("page_content_score") or 0) > 0 else "NO SIGNALS"
            ],
            [
                "WHOIS Intelligence",
                "AVAILABLE" if int(intel.get("domain_age_days") or 0) > 0 else "UNAVAILABLE"
            ],
            [
                "MalGuard AI Engine",
                "ACTIVE"
            ]
        ]

        elements.append(
            Paragraph(
                "Threat Intelligence Sources",
                heading_style
            )
        )

        elements.append(
            build_table(
                sources,
                [220, 260],
                header=True
            )
        )

    # ==========================
    # RISK METER
    # ==========================

    try:
        score_num = int(float(risk_score))

    except Exception:
        score_num = 0

    filled_blocks = max(
        0,
        min(
            int(score_num / 5),
            20
        )
    )

    empty_blocks = 20 - filled_blocks

    risk_meter_data = [
        [
            Paragraph(
                f"<b>Risk Meter:</b> {score_num}/100",
                normal_style
            )
        ],
        [
            Paragraph(
                f"{'█' * filled_blocks}{'░' * empty_blocks}",
                normal_style
            )
        ]
    ]

    risk_meter = Table(
        risk_meter_data,
        colWidths=[480]
    )

    risk_meter.setStyle(
        TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("PADDING", (0, 0), (-1, -1), 8),
        ])
    )

    elements.append(
        Paragraph(
            "Risk Visualization",
            heading_style
        )
    )

    elements.append(risk_meter)

    # ==========================
    # TECHNICAL ANALYSIS
    # ==========================

    elements.append(
        Paragraph(
            "Technical Analysis",
            heading_style
        )
    )

    elements.append(
        Paragraph(
            safe(data.get("explanation")),
            normal_style
        )
    )

    # ==========================
    # FINAL RECOMMENDATION BANNER
    # ==========================

    elements.append(
        Paragraph(
            "Final Analyst Recommendation",
            heading_style
        )
    )

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

    # ==========================
    # RECOMMENDED ACTION
    # ==========================

    elements.append(
        Paragraph(
            "Recommended Action",
            heading_style
        )
    )

    elements.append(
        Paragraph(
            safe(data.get("recommended_action")),
            normal_style
        )
    )

    # ==========================
    # MITRE
    # ==========================

    paragraph_list(
        "MITRE ATT&CK Mapping",
        data.get("mitre_attack"),
        elements,
        heading_style,
        normal_style
    )

    # ==========================
    # FOOTER
    # ==========================

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
