"""Shared PDF presentation primitives for compliance evidence reports."""

from __future__ import annotations

from pathlib import Path
from collections.abc import Sequence
from typing import Any


REPORT_FONT = "Vera"
REPORT_FONT_BOLD = "Vera-Bold"


def ensure_report_fonts() -> None:
    import reportlab
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    font_directory = Path(reportlab.__file__).parent / "fonts"
    variants = {
        REPORT_FONT: "Vera.ttf",
        REPORT_FONT_BOLD: "VeraBd.ttf",
        "Vera-Italic": "VeraIt.ttf",
        "Vera-BoldItalic": "VeraBI.ttf",
    }
    registered = set(pdfmetrics.getRegisteredFontNames())
    for name, filename in variants.items():
        if name not in registered:
            pdfmetrics.registerFont(TTFont(name, str(font_directory / filename)))
    pdfmetrics.registerFontFamily(
        REPORT_FONT,
        normal=REPORT_FONT,
        bold=REPORT_FONT_BOLD,
        italic="Vera-Italic",
        boldItalic="Vera-BoldItalic",
    )


def evidence_table(
    rows: Sequence[Sequence[Any]],
    headings: Sequence[Any],
) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    table = Table([headings, *rows], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            (
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), REPORT_FONT_BOLD),
                ("FONTNAME", (0, 1), (-1, -1), REPORT_FONT),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    (colors.white, colors.HexColor("#F3F4F6")),
                ),
                ("PADDING", (0, 0), (-1, -1), 4),
            )
        )
    )
    return table
