"""
SecureAudit — PDF Report Generator
Produces structured PDF reports with severity classification
and specific remediation recommendations.
"""
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.core.config import settings

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#DC2626"),
    "High": colors.HexColor("#EA580C"),
    "Medium": colors.HexColor("#D97706"),
    "Low": colors.HexColor("#16A34A"),
    "Informational": colors.HexColor("#2563EB"),
}


class PDFReporter:
    """
    Generates structured PDF audit reports with:
    - Executive summary with risk overview
    - Severity-classified vulnerability findings
    - Step-by-step evidence and reproduction steps
    - Specific, actionable remediation recommendations
    """

    def __init__(self):
        self.output_dir = Path(settings.report_output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self):
        """Configure custom paragraph styles for the report."""
        self.styles.add(ParagraphStyle(
            name="ReportTitle",
            parent=self.styles["Title"],
            fontSize=24,
            textColor=colors.HexColor("#1E293B"),
            spaceAfter=8,
        ))
        self.styles.add(ParagraphStyle(
            name="SectionHeader",
            parent=self.styles["Heading1"],
            fontSize=14,
            textColor=colors.HexColor("#1E293B"),
            borderPad=4,
            spaceBefore=16,
            spaceAfter=8,
        ))
        self.styles.add(ParagraphStyle(
            name="FindingTitle",
            parent=self.styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#334155"),
            spaceBefore=12,
            spaceAfter=4,
        ))
        self.styles.add(ParagraphStyle(
            name="BodyText",
            parent=self.styles["Normal"],
            fontSize=10,
            textColor=colors.HexColor("#475569"),
            spaceAfter=6,
            leading=14,
        ))
        self.styles.add(ParagraphStyle(
            name="CodeBlock",
            parent=self.styles["Code"],
            fontSize=8,
            backColor=colors.HexColor("#F1F5F9"),
            borderPad=6,
            spaceAfter=8,
        ))

    def generate(
        self,
        audit_run_id: str,
        target_url: str,
        operator: str,
        vulnerability_breakdown: dict,
        findings: list[dict],
        started_at: str,
        completed_at: str,
    ) -> str:
        """
        Generate a complete PDF audit report.

        Args:
            audit_run_id: Unique ID of the audit run
            target_url: URL of the audited application
            operator: Name/ID of the operator who ran the audit
            vulnerability_breakdown: Dict of severity → list of vuln classes
            findings: List of confirmed vulnerability finding dicts
            started_at, completed_at: ISO timestamps

        Returns:
            Path to the generated PDF file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"audit_{audit_run_id[:8]}_{timestamp}.pdf"
        filepath = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )

        story = []

        # ── Cover ─────────────────────────────────────────────────────────────
        story.append(Paragraph("🔒 SecureAudit", self.styles["ReportTitle"]))
        story.append(Paragraph("Security Audit Report", self.styles["Heading2"]))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1E293B")))
        story.append(Spacer(1, 0.5 * cm))

        meta_data = [
            ["Target URL", target_url],
            ["Audit Run ID", audit_run_id],
            ["Operator", operator],
            ["Started", started_at],
            ["Completed", completed_at],
        ]
        meta_table = Table(meta_data, colWidths=[4 * cm, 13 * cm])
        meta_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748B")),
            ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#1E293B")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 1 * cm))

        # ── Executive Summary ─────────────────────────────────────────────────
        story.append(Paragraph("Executive Summary", self.styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))

        total_findings = sum(len(v) for v in vulnerability_breakdown.values())
        critical_count = len(vulnerability_breakdown.get("Critical", []))
        high_count = len(vulnerability_breakdown.get("High", []))

        summary_text = (
            f"This automated security audit of <b>{target_url}</b> identified "
            f"<b>{total_findings} confirmed vulnerabilities</b> across {len(findings)} test cases. "
            f"Of these, <b>{critical_count} are Critical</b> and <b>{high_count} are High</b> severity, "
            f"requiring immediate remediation. All findings include reproduction steps and specific remediation guidance."
        )
        story.append(Paragraph(summary_text, self.styles["BodyText"]))
        story.append(Spacer(1, 0.5 * cm))

        # Severity summary table
        severity_headers = ["Severity", "Count", "Vulnerability Classes"]
        severity_rows = [severity_headers]
        for sev in ["Critical", "High", "Medium", "Low"]:
            classes = vulnerability_breakdown.get(sev, [])
            severity_rows.append([sev, str(len(classes)), ", ".join(classes) or "None"])

        sev_table = Table(severity_rows, colWidths=[4 * cm, 3 * cm, 10 * cm])
        sev_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("PADDING", (0, 0), (-1, -1), 8),
        ]
        for i, sev in enumerate(["Critical", "High", "Medium", "Low"], start=1):
            color = SEVERITY_COLORS.get(sev, colors.gray)
            sev_style.append(("TEXTCOLOR", (0, i), (0, i), color))
            sev_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))

        sev_table.setStyle(TableStyle(sev_style))
        story.append(sev_table)
        story.append(Spacer(1, 1 * cm))

        # ── Detailed Findings ──────────────────────────────────────────────────
        story.append(Paragraph("Detailed Findings", self.styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E2E8F0")))

        for idx, finding in enumerate(findings, start=1):
            severity = finding.get("severity", "Medium")
            sev_color = SEVERITY_COLORS.get(severity, colors.gray)

            story.append(Paragraph(
                f"Finding {idx}: {finding.get('goal', 'Unknown')}",
                self.styles["FindingTitle"],
            ))

            detail_rows = [
                ["Severity", finding.get("severity", "—")],
                ["Vulnerability Class", finding.get("vulnerability_class", "—")],
                ["Status", finding.get("status", "—")],
                ["Steps Passed", str(finding.get("steps_passed", 0))],
                ["Steps Failed", str(finding.get("steps_failed", 0))],
            ]
            detail_table = Table(detail_rows, colWidths=[4 * cm, 13 * cm])
            detail_table.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748B")),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
                ("PADDING", (0, 0), (-1, -1), 6),
                ("TEXTCOLOR", (1, 0), (1, 0), sev_color),
                ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
            ]))
            story.append(detail_table)

            if finding.get("evidence"):
                story.append(Paragraph("<b>Evidence:</b>", self.styles["BodyText"]))
                story.append(Paragraph(finding["evidence"], self.styles["CodeBlock"]))

            if finding.get("remediation"):
                story.append(Paragraph("<b>Remediation:</b>", self.styles["BodyText"]))
                story.append(Paragraph(finding["remediation"], self.styles["BodyText"]))

            story.append(Spacer(1, 0.5 * cm))

        doc.build(story)
        logger.info(f"PDF report generated: {filepath}")
        return str(filepath)
