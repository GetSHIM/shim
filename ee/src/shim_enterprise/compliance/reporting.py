"""Shared presentation and counting primitives for compliance evidence reports."""

from __future__ import annotations

from datetime import datetime
import io
from pathlib import Path
from collections.abc import Sequence
from typing import Any

from sqlalchemy import Integer, Select, case, cast, func, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from shim_enterprise.billing.models import RequestLifecycle


REPORT_FONT = "Vera"
REPORT_FONT_BOLD = "Vera-Bold"
NOT_RECORDED = "bu sürümde kaydedilmiyor"
# Table cells do not wrap, so a count column breaks the phrase to stay narrow.
NOT_RECORDED_CELL = "bu sürümde\nkaydedilmiyor"


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


def report_styles() -> Any:
    """reportlab's sample stylesheet with the report fonts on the styles reports use."""
    from reportlab.lib.styles import getSampleStyleSheet

    ensure_report_fonts()
    styles = getSampleStyleSheet()
    for style_name, font in (
        ("Title", REPORT_FONT_BOLD),
        ("Heading2", REPORT_FONT_BOLD),
        ("Heading3", REPORT_FONT_BOLD),
        ("Normal", REPORT_FONT),
    ):
        styles[style_name].fontName = font
    return styles


def build_pdf(story: list[Any], title: str, *, side_margin: float = 18) -> bytes:
    """An A4 document, 18 mm top and bottom and `side_margin` mm left and right."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate

    output = io.BytesIO()
    SimpleDocTemplate(
        output,
        pagesize=A4,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        leftMargin=side_margin * mm,
        rightMargin=side_margin * mm,
        title=title,
    ).build(story)
    return output.getvalue()


def evidence_table(
    rows: Sequence[Sequence[Any]],
    headings: Sequence[Any],
    col_widths: Sequence[float] | None = None,
) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Table, TableStyle

    table = Table([headings, *rows], colWidths=col_widths, hAlign="LEFT")
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


def safe_csv(value: object | None) -> str:
    """A CSV cell a spreadsheet will not read as a formula."""
    if isinstance(value, datetime):
        value = value.isoformat()
    rendered = "" if value is None else str(value)
    return (
        f"'{rendered}"
        if rendered.lstrip().startswith(("=", "+", "-", "@"))
        else rendered
    )


def lifecycle_window(tenant_id: Any, start: datetime, end: datetime) -> tuple[Any, ...]:
    """One tenant's request_lifecycle rows started in a closed window."""
    return (
        RequestLifecycle.organization_id == tenant_id,
        RequestLifecycle.started_at >= start,
        RequestLifecycle.started_at <= end,
    )


def lifecycle_object(key: str) -> Any:
    """One request_lifecycle metadata map, empty when absent or not an object."""
    # Older rows lack the key and a failed scan stores null; both count as empty.
    value = RequestLifecycle.lifecycle_metadata[key]
    return case((func.jsonb_typeof(value) == "object", value), else_=cast({}, JSONB))


def entity_sums(key: str, window: Sequence[Any], *group_by: Any) -> Select[Any]:
    """Per entity type, the summed counts of one metadata map over the window.

    Columns: the `group_by` expressions, `entity_type`, the sum.
    """
    entries = (
        func.jsonb_each_text(lifecycle_object(key))
        .table_valued("key", "value")
        .lateral()
    )
    return (
        select(
            *group_by,
            entries.c.key.label("entity_type"),
            func.sum(cast(entries.c.value, Integer)),
        )
        .select_from(RequestLifecycle)
        .join(entries, true())
        .where(*window)
        .group_by(*group_by, entries.c.key)
    )


async def recorded_entity_sums(
    session: AsyncSession, key: str, window: Sequence[Any], *group_by: Any
) -> list[Any] | None:
    """`entity_sums` rows, or None when no row in the window recorded the key."""
    if not await session.scalar(
        select(RequestLifecycle.id)
        .where(*window, RequestLifecycle.lifecycle_metadata.has_key(key))
        .limit(1)
    ):
        return None
    return list(await session.execute(entity_sums(key, window, *group_by)))
