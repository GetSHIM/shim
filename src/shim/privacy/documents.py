"""The text of PDF, Word and text files, read in memory within fixed bounds."""

from __future__ import annotations

import base64
import binascii
import io
import re
import time
from xml.etree import ElementTree
import zipfile

from shim.gateway.media import MediaPart, split_data_url

DOCUMENT_TEXT_VERSION = 1
MAX_DECODED_BYTES = 32 * 1024 * 1024
MAX_DOCUMENT_CHARS = 1_000_000
MAX_REQUEST_CHARS = 4_000_000
MAX_SECONDS = 10.0
MAX_PDF_PAGES = 1_000
# Fewer non-whitespace characters a page than this is a scan without a text layer.
MIN_PAGE_CHARS = 20
MAX_ZIP_ENTRIES = 1_000
MAX_DOCX_PART_BYTES = 20 * 1024 * 1024
MAX_DOCX_TOTAL_BYTES = 50 * 1024 * 1024
TEXT_MIMES = frozenset({"text/plain", "text/markdown", "text/csv", "application/json"})
# How a clean PDF goes to each provider with document_format by_provider, as of
# 2026-10-08: Anthropic bills a page as its text plus a page image and OpenAI puts
# both in context (docs.anthropic.com/en/docs/build-with-claude/pdf-support,
# platform.openai.com/docs/guides/pdf-files), so text is cheaper; Gemini 3 bills
# page images only and the native text is free (ai.google.dev/gemini-api/docs/document-processing).
DOCUMENT_FORMAT_V1 = {"anthropic": "text", "openai": "text", "google": "native"}

_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_DOCTYPE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_DOCX_TEXT_PARTS = re.compile(
    r"word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml"
)


class Unscannable(Exception):
    """A document whose text cannot be read; `reason` is a fixed word, never content."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def is_document(part: MediaPart) -> bool:
    return part.kind in {"pdf", "docx"} or (
        part.kind == "text" and (part.mime is None or part.mime in TEXT_MIMES)
    )


def extract_text(part: MediaPart, data: str | None) -> str:
    """The text of an inline document, or `Unscannable` with the reason."""
    if part.source != "inline" or data is None:
        raise Unscannable("not_inline")
    if (part.decoded_bytes or 0) > MAX_DECODED_BYTES:
        raise Unscannable("too_large")
    _, encoded = split_data_url(data)
    try:
        raw = base64.b64decode(encoded.replace("-", "+").replace("_", "/"))
    except (binascii.Error, ValueError):
        raise Unscannable("corrupt") from None
    deadline = time.monotonic() + MAX_SECONDS
    if part.kind == "pdf":
        text = _pdf(raw, deadline)
    elif part.kind == "docx":
        text = _docx(raw, deadline)
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise Unscannable("corrupt") from None
    if len(text) > MAX_DOCUMENT_CHARS:
        raise Unscannable("too_large")
    return text


def pdf_reader_version() -> str | None:
    try:
        import pypdf
    except ImportError:
        return None
    return pypdf.__version__


def _pdf(raw: bytes, deadline: float) -> str:
    try:
        import pypdf
    except ImportError:
        raise Unscannable("needs_pypdf") from None
    texts: list[str] = []
    try:
        reader = pypdf.PdfReader(io.BytesIO(raw))
        if reader.is_encrypted:
            raise Unscannable("encrypted")
        pages = reader.pages
        if len(pages) > MAX_PDF_PAGES:
            raise Unscannable("too_large")
        characters = 0
        for page in pages:
            if time.monotonic() > deadline:
                raise Unscannable("too_slow")
            texts.append(page.extract_text() or "")
            characters += len(texts[-1])
            if characters > MAX_DOCUMENT_CHARS:
                raise Unscannable("too_large")
    except Unscannable:
        raise
    # Hostile input: whatever the parser raises, the file is unreadable.
    except Exception:
        raise Unscannable("corrupt") from None
    if not texts:
        raise Unscannable("corrupt")
    if sum(len("".join(text.split())) for text in texts) < MIN_PAGE_CHARS * len(texts):
        raise Unscannable("no_text_layer")
    return "\n".join(texts)


def _docx(raw: bytes, deadline: float) -> str:
    paragraphs: list[str] = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
        entries = archive.infolist()
        if len(entries) > MAX_ZIP_ENTRIES or (
            any(entry.file_size > MAX_DOCX_PART_BYTES for entry in entries)
            or sum(entry.file_size for entry in entries) > MAX_DOCX_TOTAL_BYTES
        ):
            raise Unscannable("too_large")
        parts = sorted(
            (entry for entry in entries if _DOCX_TEXT_PARTS.fullmatch(entry.filename)),
            key=lambda entry: entry.filename != "word/document.xml",
        )
        if not parts or parts[0].filename != "word/document.xml":
            raise Unscannable("corrupt")
        for entry in parts:
            if time.monotonic() > deadline:
                raise Unscannable("too_slow")
            with archive.open(entry) as stream:
                xml = stream.read(entry.file_size + 1)
            # A part longer than it declares, or one that could define entities.
            if len(xml) > entry.file_size or _DOCTYPE.search(xml):
                raise Unscannable("corrupt")
            root = ElementTree.fromstring(xml)
            paragraphs += [
                "".join(run.text or "" for run in paragraph.iter(f"{_W}t"))
                for paragraph in root.iter(f"{_W}p")
            ]
    except Unscannable:
        raise
    # Hostile input: a bad zip, compression or XML is an unreadable file.
    except Exception:
        raise Unscannable("corrupt") from None
    return "\n".join(paragraphs)
