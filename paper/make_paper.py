"""
Render the GuardRail paper to a two-column PDF.

    python paper/make_paper.py

Output: paper/guardrail_paper.pdf
"""

import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether,
                                NextPageTemplate, PageBreak, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from paper_content import (ABSTRACT, AFFIL, AUTHORS, BODY, EMAIL,  # noqa: E402
                           KEYWORDS, TABLES, TITLE)

OUT = Path(__file__).resolve().parent / "guardrail_paper.pdf"

PAGE_W, PAGE_H = LETTER
MARGIN = 0.72 * inch
GUTTER = 0.28 * inch
COL_W = (PAGE_W - 2 * MARGIN - GUTTER) / 2

BODY_FONT = "Times-Roman"
BOLD_FONT = "Times-Bold"
ITAL_FONT = "Times-Italic"

S = {
    "title": ParagraphStyle("title", fontName=BOLD_FONT, fontSize=17, leading=20.5,
                            alignment=TA_CENTER, spaceAfter=9),
    "author": ParagraphStyle("author", fontName=BODY_FONT, fontSize=10.5, leading=13,
                             alignment=TA_CENTER, spaceAfter=1),
    "affil": ParagraphStyle("affil", fontName=ITAL_FONT, fontSize=9, leading=11,
                            alignment=TA_CENTER, spaceAfter=13),
    "abshead": ParagraphStyle("abshead", fontName=BOLD_FONT, fontSize=9.5, leading=12,
                              spaceAfter=3),
    "abstract": ParagraphStyle("abstract", fontName=BODY_FONT, fontSize=9, leading=11.3,
                               alignment=TA_JUSTIFY, spaceAfter=6),
    "kw": ParagraphStyle("kw", fontName=BODY_FONT, fontSize=8.7, leading=11,
                         alignment=TA_JUSTIFY, spaceAfter=10),
    "h1": ParagraphStyle("h1", fontName=BOLD_FONT, fontSize=11, leading=13,
                         spaceBefore=9, spaceAfter=4),
    "h2": ParagraphStyle("h2", fontName=BOLD_FONT, fontSize=9.6, leading=12,
                         spaceBefore=7, spaceAfter=3),
    "p": ParagraphStyle("p", fontName=BODY_FONT, fontSize=9.2, leading=11.4,
                        alignment=TA_JUSTIFY, spaceAfter=5, firstLineIndent=10),
    "p0": ParagraphStyle("p0", fontName=BODY_FONT, fontSize=9.2, leading=11.4,
                         alignment=TA_JUSTIFY, spaceAfter=5),
    "ref": ParagraphStyle("ref", fontName=BODY_FONT, fontSize=8.1, leading=9.9,
                          alignment=TA_JUSTIFY, spaceAfter=3.2,
                          leftIndent=11, firstLineIndent=-11),
    "cap": ParagraphStyle("cap", fontName=BODY_FONT, fontSize=8.0, leading=9.7,
                          alignment=TA_JUSTIFY, spaceBefore=3, spaceAfter=7),
    "url": ParagraphStyle("url", fontName=BODY_FONT, fontSize=8, leading=10,
                          spaceBefore=1, spaceAfter=6),
    "note": ParagraphStyle("note", fontName=ITAL_FONT, fontSize=7.4, leading=9,
                           spaceBefore=1, spaceAfter=7),
}


def build_table(key):
    spec = TABLES[key]
    head, rows = spec["head"], spec["rows"]
    cell = ParagraphStyle("cell", fontName=BODY_FONT, fontSize=7.8, leading=9.3)
    cellb = ParagraphStyle("cellb", fontName=BOLD_FONT, fontSize=7.8, leading=9.3)
    cellr = ParagraphStyle("cellr", fontName=BODY_FONT, fontSize=7.8, leading=9.3,
                           alignment=2)
    cellbr = ParagraphStyle("cellbr", fontName=BOLD_FONT, fontSize=7.8, leading=9.3,
                            alignment=2)

    data = [[Paragraph(h, cellb if i == 0 else cellbr) for i, h in enumerate(head)]]
    for r in rows:
        bold = r[0] in ("overall", "FPR on clean")
        data.append([Paragraph(c, (cellb if bold else cell) if i == 0
                               else (cellbr if bold else cellr))
                     for i, c in enumerate(r)])

    ncol = len(head)
    first = COL_W * (0.44 if ncol > 3 else 0.52)
    rest = (COL_W - first) / (ncol - 1)
    t = Table(data, colWidths=[first] + [rest] * (ncol - 1), hAlign="LEFT")
    t.setStyle(TableStyle([
        ("LINEABOVE", (0, 0), (-1, 0), 0.7, colors.black),
        ("LINEBELOW", (0, 0), (-1, 0), 0.45, colors.black),
        ("LINEBELOW", (0, -1), (-1, -1), 0.7, colors.black),
        ("TOPPADDING", (0, 0), (-1, -1), 1.7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.7),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))

    parts = [t, Paragraph(spec["caption"], S["cap"])]
    if spec.get("note"):
        parts.insert(1, Paragraph(spec["note"], S["note"]))
    return KeepTogether(parts)


def main():
    doc = BaseDocTemplate(str(OUT), pagesize=LETTER,
                          leftMargin=MARGIN, rightMargin=MARGIN,
                          topMargin=MARGIN, bottomMargin=MARGIN,
                          title=TITLE, author=AUTHORS)

    full_w = PAGE_W - 2 * MARGIN
    # Page 1: full-width banner for title/abstract, then two columns beneath it.
    banner_h = 3.42 * inch
    f_banner = Frame(MARGIN, PAGE_H - MARGIN - banner_h, full_w, banner_h, id="ban",
                     leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    col_h1 = PAGE_H - 2 * MARGIN - banner_h
    f_l1 = Frame(MARGIN, MARGIN, COL_W, col_h1, id="l1",
                 leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    f_r1 = Frame(MARGIN + COL_W + GUTTER, MARGIN, COL_W, col_h1, id="r1",
                 leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)

    col_h = PAGE_H - 2 * MARGIN
    f_l = Frame(MARGIN, MARGIN, COL_W, col_h, id="l",
                leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    f_r = Frame(MARGIN + COL_W + GUTTER, MARGIN, COL_W, col_h, id="r",
                leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont(BODY_FONT, 8)
        canvas.drawCentredString(PAGE_W / 2, MARGIN * 0.55, str(d.page))
        canvas.restoreState()

    doc.addPageTemplates([
        PageTemplate(id="first", frames=[f_banner, f_l1, f_r1], onPage=footer),
        PageTemplate(id="rest", frames=[f_l, f_r], onPage=footer),
    ])

    story = [
        Paragraph(TITLE, S["title"]),
        Paragraph(AUTHORS, S["author"]),
        Paragraph(f"{AFFIL} &middot; {EMAIL}", S["affil"]),
        Paragraph("Abstract", S["abshead"]),
        Paragraph(ABSTRACT, S["abstract"]),
        Paragraph(f"<b>Keywords:</b> {KEYWORDS}", S["kw"]),
        NextPageTemplate("rest"),
    ]

    prev = None
    for kind, text in BODY:
        if kind in TABLES:
            story.append(build_table(kind))
        elif kind == "p":
            # No indent on the first paragraph after a heading.
            story.append(Paragraph(text, S["p0"] if prev in ("h1", "h2") else S["p"]))
        else:
            story.append(Paragraph(text, S[kind]))
        prev = kind

    doc.build(story)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
