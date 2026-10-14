"""The text of PDF, Word and text files, read in memory within fixed bounds."""

from __future__ import annotations

import base64
import binascii
import io
import re
import time
from typing import IO
from xml.parsers import expat
import zipfile

from shim.core import isolation
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
# XML elements one Word file may hold; a long document has a few hundred thousand.
MAX_DOCX_ELEMENTS = 1_000_000
# pypdf's own limits are 75 MB a stream; a page of text decodes to well under 1 MB.
_PDF_LIMITS = {
    **dict.fromkeys(
        (
            "maximum_declared_stream_length",
            "array_based_stream_maximum_output_length",
            "jbig2_maximum_output_length",
            "lzw_maximum_output_length",
            "run_length_maximum_output_length",
            "zlib_maximum_output_length",
            "brotli_maximum_output_length",
            "image_maximum_buffer_size",
        ),
        4 * 1024 * 1024,
    ),
    "stream_decoding_work_maximum_length": 16 * 1024 * 1024,
    # Never run an external decoder on a client's file.
    "jbig2dec_binary": None,
}
TEXT_MIMES = frozenset({"text/plain", "text/markdown", "text/csv", "application/json"})
# How a clean PDF goes to each provider with document_format by_provider, as of
# 2026-10-08: Anthropic bills a page as its text plus a page image and OpenAI puts
# both in context (docs.anthropic.com/en/docs/build-with-claude/pdf-support,
# platform.openai.com/docs/guides/pdf-files), so text is cheaper; Gemini 3 bills
# page images only and the native text is free (ai.google.dev/gemini-api/docs/document-processing).
DOCUMENT_FORMAT_V1 = {"anthropic": "text", "openai": "text", "google": "native"}

_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main "
_DOCX_TEXT = frozenset({f"{_W}t", f"{_W}delText"})
_DOCX_TEXT_PARTS = re.compile(
    r"word/(document|header\d*|footer\d*|footnotes|endnotes|comments"
    r"|glossary/document)\.xml"
)
# Author, title and custom properties: every value in them is text.
_DOCX_PROPERTY_PARTS = frozenset({"docProps/core.xml", "docProps/custom.xml"})
_SURROGATE = re.compile("[\ud800-\udfff]")


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
    # pypdf passes lone surrogates through; they cannot be encoded in a provider body.
    return _SURROGATE.sub("\ufffd", text)


def read_document(part: MediaPart, data: str | None, deadline: float) -> str:
    """`extract_text`, with an inline PDF read in an isolated worker by `deadline`."""
    if (
        part.kind != "pdf"
        or part.source != "inline"
        or data is None
        or (part.decoded_bytes or 0) > MAX_DECODED_BYTES
    ):
        return extract_text(part, data)
    try:
        return isolation.run(extract_text, part, data, deadline=deadline)
    except TimeoutError:
        raise Unscannable("too_slow") from None
    except MemoryError:
        raise Unscannable("too_large") from None


def pdf_reader_version() -> str | None:
    try:
        import pypdf
    except ImportError:
        return None
    return pypdf.__version__


def _pdf(raw: bytes, deadline: float) -> str:
    try:
        import pypdf
        from pypdf.errors import LimitReachedError
    except ImportError:
        raise Unscannable("needs_pypdf") from None
    texts: list[str] = []
    extras: list[str] = []
    try:
        limits = pypdf.get_configuration().with_overwrites(**_PDF_LIMITS)
        with pypdf.apply_configuration(limits):
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
                # What a viewer draws over the page: notes, stamps, free text.
                for annotation in page.get("/Annots") or ():
                    contents = annotation.get_object().get("/Contents")
                    if contents is not None:
                        extras.append(str(contents))
                characters += len(texts[-1])
                if characters > MAX_DOCUMENT_CHARS:
                    raise Unscannable("too_large")
            # Filled-in form values and the document information are drawn or shown too.
            extras += [
                str(field["/V"])
                for field in (reader.get_fields() or {}).values()
                if field.get("/V") is not None
            ]
            extras += [str(value) for value in (reader.metadata or {}).values()]
    except Unscannable:
        raise
    except MemoryError:
        raise Unscannable("too_large") from None
    except LimitReachedError:
        raise Unscannable("too_large") from None
    # Hostile input: whatever the parser raises, the file is unreadable.
    except Exception:
        raise Unscannable("corrupt") from None
    if not texts:
        raise Unscannable("corrupt")
    if sum(len("".join(text.split())) for text in texts) < MIN_PAGE_CHARS * len(texts):
        raise Unscannable("no_text_layer")
    return "\n".join(texts + extras)


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
            (
                entry
                for entry in entries
                if _DOCX_TEXT_PARTS.fullmatch(entry.filename)
                or entry.filename in _DOCX_PROPERTY_PARTS
            ),
            key=lambda entry: entry.filename != "word/document.xml",
        )
        if not parts or parts[0].filename != "word/document.xml":
            raise Unscannable("corrupt")
        elements = [0]
        for entry in parts:
            with archive.open(entry) as stream:
                paragraphs += _xml_text(
                    stream,
                    entry.file_size,
                    every=entry.filename in _DOCX_PROPERTY_PARTS,
                    elements=elements,
                    deadline=deadline,
                )
    except Unscannable:
        raise
    except MemoryError:
        raise Unscannable("too_large") from None
    # Hostile input: a bad zip, compression or XML is an unreadable file.
    except Exception:
        raise Unscannable("corrupt") from None
    return "\n".join(paragraphs)


def _refuse(*_: object) -> None:
    # A DTD can define entities that expand; refused in any encoding.
    raise Unscannable("corrupt")


def _xml_text(
    stream: IO[bytes],
    declared: int,
    *,
    every: bool,
    elements: list[int],
    deadline: float,
) -> list[str]:
    """The text of each `w:p` paragraph, or of every element when `every`, read
    incrementally: no tree is built, and `elements` counts across the parts."""
    parser = expat.ParserCreate(namespace_separator=" ")
    texts: list[str] = []
    open_paragraphs: list[list[str]] = []
    reading = [every]

    def start(name: str, _: object) -> None:
        elements[0] += 1
        if elements[0] > MAX_DOCX_ELEMENTS:
            raise Unscannable("too_large")
        if every:
            open_paragraphs.append([])
        elif name == f"{_W}p":
            open_paragraphs.append([])
        elif name in _DOCX_TEXT:
            reading[0] = True

    def end(name: str) -> None:
        if every or name == f"{_W}p":
            text = "".join(open_paragraphs.pop())
            if text or not every:
                texts.append(text)
        elif name in _DOCX_TEXT:
            reading[0] = False

    def data(text: str) -> None:
        if reading[0] and open_paragraphs:
            open_paragraphs[-1].append(text)

    parser.StartDoctypeDeclHandler = _refuse
    parser.EntityDeclHandler = _refuse
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = data
    read = 0
    while chunk := stream.read(65_536):
        read += len(chunk)
        # A part longer than it declares.
        if read > declared:
            raise Unscannable("corrupt")
        if time.monotonic() > deadline:
            raise Unscannable("too_slow")
        parser.Parse(chunk, False)
    parser.Parse(b"", True)
    return texts
