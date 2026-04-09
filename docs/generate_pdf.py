#!/usr/bin/env python3
"""
Generate PDF documentation from the ThreatTrace text documentation.
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak,
    Table,
    TableStyle,
    ListFlowable,
    ListItem,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing
from reportlab.lib.colors import HexColor

import os

INPUT_FILE = os.path.join(os.path.dirname(__file__), "THREATTRACE_DOCUMENTATION.txt")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "THREATTRACE_DOCUMENTATION.pdf")


def read_text_file(filepath):
    """Read the text file and return its content."""
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def parse_sections(content):
    """Parse the text content into sections."""
    lines = content.split("\n")
    sections = []
    current_section = None
    current_content = []

    for line in lines:
        if line.startswith("=" * 80) or line.startswith("=" * 79):
            if current_section:
                sections.append((current_section, "\n".join(current_content)))
            current_section = None
            current_content = []
        elif line.strip().endswith(":") and not line.startswith(" "):
            if current_section and current_content:
                sections.append((current_section, "\n".join(current_content)))
            current_section = line.strip()
            current_content = []
        elif current_section:
            current_content.append(line)
        elif line.startswith("TABLE OF CONTENTS"):
            current_section = "TABLE OF CONTENTS"
            current_content = [line]

    if current_section and current_content:
        sections.append((current_section, "\n".join(current_content)))

    return sections


def create_document():
    """Create the PDF document."""
    doc = SimpleDocTemplate(
        OUTPUT_FILE,
        pagesize=A4,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=HexColor("#1a1a2e"),
    )

    heading_style = ParagraphStyle(
        "CustomHeading",
        parent=styles["Heading1"],
        fontSize=14,
        spaceAfter=12,
        spaceBefore=20,
        textColor=HexColor("#16213e"),
        borderPadding=5,
        borderColor=HexColor("#00d4ff"),
        borderWidth=1,
    )

    subheading_style = ParagraphStyle(
        "CustomSubheading",
        parent=styles["Heading2"],
        fontSize=12,
        spaceAfter=8,
        spaceBefore=12,
        textColor=HexColor("#0f3460"),
    )

    body_style = ParagraphStyle(
        "CustomBody",
        parent=styles["BodyText"],
        fontSize=9,
        alignment=TA_JUSTIFY,
        spaceAfter=6,
        leading=14,
    )

    code_style = ParagraphStyle(
        "Code",
        parent=styles["Code"],
        fontSize=8,
        spaceAfter=4,
        leftIndent=20,
        fontName="Courier",
    )

    story = []

    # Title
    story.append(Paragraph("ThreatTrace Project Documentation", title_style))
    story.append(Spacer(1, 20))
    story.append(Paragraph("Comprehensive Technical Reference", body_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph("Version 2.0 | March 2026 | TLP: AMBER", body_style))
    story.append(PageBreak())

    # Read the text file
    content = read_text_file(INPUT_FILE)

    # Parse and add sections
    in_table_of_contents = False
    current_heading = None

    lines = content.split("\n")

    for i, line in enumerate(lines):
        line_stripped = line.strip()

        # Skip title separators
        if line_stripped.startswith("=" * 60):
            continue

        # Handle main headings
        if line_stripped.startswith("EXECUTIVE OVERVIEW"):
            story.append(Paragraph("1. EXECUTIVE OVERVIEW", heading_style))
            current_heading = "Executive Overview"
        elif line_stripped.startswith("SYSTEM DESIGN ARCHITECTURE"):
            story.append(Paragraph("2. SYSTEM DESIGN ARCHITECTURE", heading_style))
            current_heading = "System Design"
        elif line_stripped.startswith("TOOLS AND TECHNOLOGIES"):
            story.append(Paragraph("3. TOOLS AND TECHNOLOGIES", heading_style))
            current_heading = "Tools"
        elif line_stripped.startswith("PROJECT STRUCTURE"):
            story.append(Paragraph("4. PROJECT STRUCTURE", heading_style))
            current_heading = "Structure"
        elif line_stripped.startswith("COMPLETE WORKFLOW"):
            story.append(Paragraph("5. COMPLETE WORKFLOW", heading_style))
            current_heading = "Workflow"
        elif line_stripped.startswith("MODULE DETAILS"):
            story.append(Paragraph("6. MODULE DETAILS", heading_style))
            current_heading = "Modules"
        elif "CORE MODULES" in line_stripped:
            story.append(Paragraph("6.1 Core Modules", subheading_style))
        elif "PARSERS" in line_stripped:
            story.append(Paragraph("6.2 Parsers", subheading_style))
        elif "DETECTION ENGINE" in line_stripped:
            story.append(Paragraph("6.3 Detection Engine", subheading_style))
        elif "ANALYTICS MODULES" in line_stripped:
            story.append(Paragraph("6.4 Analytics Modules", subheading_style))
        elif "REPORT BUILDER" in line_stripped:
            story.append(Paragraph("6.5 Report Builder", subheading_style))
        elif line_stripped.startswith("CONFIGURATION"):
            story.append(Paragraph("7. CONFIGURATION", heading_style))
        elif line_stripped.startswith("USAGE EXAMPLES"):
            story.append(Paragraph("8. USAGE EXAMPLES", heading_style))
        elif line_stripped.startswith("DETECTION RULES"):
            story.append(Paragraph("9. DETECTION RULES", heading_style))
        elif line_stripped.startswith("OUTPUT FORMATS"):
            story.append(Paragraph("10. OUTPUT FORMATS", heading_style))
        elif line_stripped.startswith("TABLE OF CONTENTS"):
            in_table_of_contents = True
        elif "END OF DOCUMENTATION" in line_stripped:
            break
        elif line_stripped and current_heading:
            # Add as body text with proper formatting
            if line_stripped.startswith("- "):
                # Bullet point
                clean_text = line_stripped[2:]
                story.append(Paragraph(f"• {clean_text}", body_style))
            elif line_stripped.startswith("+"):
                # Code/command line
                story.append(
                    Paragraph(
                        f"<font face='Courier'>{line_stripped}</font>", code_style
                    )
                )
            elif line_stripped.startswith("|"):
                # Table row - skip for now
                continue
            elif ":" in line_stripped and not line_stripped.startswith(" "):
                # Key-value pair
                story.append(Paragraph(f"<b>{line_stripped}</b>", body_style))
            elif line_stripped.startswith("  ") and not line_stripped.startswith("   "):
                # Indented - sub-bullet
                story.append(
                    Paragraph(f"&nbsp;&nbsp;{line_stripped.strip()}", body_style)
                )
            elif len(line_stripped) > 10:
                # Regular paragraph
                story.append(Paragraph(line_stripped, body_style))

    # Build the PDF
    doc.build(story)
    print(f"PDF generated: {OUTPUT_FILE}")


if __name__ == "__main__":
    create_document()
