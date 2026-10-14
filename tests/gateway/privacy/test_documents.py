import base64
import io
import sys
from xml.sax.saxutils import escape
import zipfile

from fastapi import HTTPException
import pytest

import shim.privacy.documents as documents
from shim.gateway.media import classify_media
from shim.gateway.pipeline.privacy import DocumentReport, scrub_payload
from shim.privacy.documents import (
    MAX_DOCUMENT_CHARS,
    MAX_PDF_PAGES,
    Unscannable,
    extract_text,
)
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import effective_entity_actions

DEFAULT_ACTIONS = effective_entity_actions()
_FONT = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"


def _pdf(*pages: str, encrypt: bool = False) -> bytes:
    """A PDF with one uncompressed Helvetica text stream per page."""
    count = len(pages)
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [%s] /Count %d >>"
        % (b" ".join(b"%d 0 R" % (4 + 2 * index) for index in range(count)), count),
        _FONT,
    ]
    for index, text in enumerate(pages):
        body = (
            b"BT /F1 12 Tf 72 720 Td (%s) Tj ET" % text.encode("latin-1")
            if text
            else b"q 1 0 0 1 0 0 cm Q"
        )
        objects += [
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R "
            b"/Resources << /Font << /F1 3 0 R >> >> >>" % (5 + 2 * index),
            b"<< /Length %d >>\nstream\n%s\nendstream" % (len(body), body),
        ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (number, body)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    encryption = (
        b" /Encrypt << /Filter /Standard /V 1 /R 2 /O <%s> /U <%s> /P -44 >>"
        b" /ID [<%s> <%s>]" % (b"00" * 32, b"00" * 32, b"00" * 16, b"00" * 16)
        if encrypt
        else b""
    )
    out += b"trailer\n<< /Size %d /Root 1 0 R%s >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        encryption,
        xref,
    )
    return bytes(out)


def _docx(*paragraphs: str, extra: dict[str, str] | None = None) -> bytes:
    def xml(root: str, inner: str) -> str:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<w:{root} xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            f"{inner}</w:{root}>"
        )

    body = "".join(
        f"<w:p><w:r><w:t>{escape(text)}</w:t></w:r></w:p>" for text in paragraphs
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr(
            "word/document.xml", xml("document", f"<w:body>{body}</w:body>")
        )
        for name, text in (extra or {}).items():
            archive.writestr(
                name, xml("hdr", f"<w:p><w:r><w:t>{escape(text)}</w:t></w:r></w:p>")
            )
    return buffer.getvalue()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _part(kind: str, data: bytes, mime: str):
    (part,) = classify_media(
        {
            "contents": [
                {"parts": [{"inlineData": {"mimeType": mime, "data": _b64(data)}}]}
            ]
        }
    )
    assert part.kind == kind
    return part, _b64(data)


def _text_of(kind: str, data: bytes, mime: str) -> str:
    return extract_text(*_part(kind, data, mime))


def _reason(kind: str, data: bytes, mime: str) -> str:
    with pytest.raises(Unscannable) as unscannable:
        _text_of(kind, data, mime)
    return unscannable.value.reason


TEXT_PAGE = "Rapor hazir, ekip onayladi."


def test_pdf_text_is_read_page_by_page() -> None:
    text = _text_of(
        "pdf", _pdf(TEXT_PAGE, "Ikinci sayfa da okunur."), "application/pdf"
    )

    assert "Rapor hazir" in text and "Ikinci sayfa" in text


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (_pdf(TEXT_PAGE, encrypt=True), "encrypted"),
        (_pdf(TEXT_PAGE)[:200], "corrupt"),
        (b"%PDF-1.4 nothing else", "corrupt"),
        (_pdf(""), "no_text_layer"),
    ],
)
def test_unreadable_pdfs_name_their_reason(data, reason) -> None:
    assert _reason("pdf", data, "application/pdf") == reason


def test_a_text_layer_needs_twenty_characters_a_page() -> None:
    assert _text_of("pdf", _pdf("x" * 20, "y" * 20), "application/pdf")
    assert (
        _reason("pdf", _pdf("x" * 20, "y" * 19), "application/pdf") == "no_text_layer"
    )


def test_pdf_page_count_is_bounded(monkeypatch) -> None:
    monkeypatch.setattr(documents, "MAX_PDF_PAGES", 3)
    assert _text_of("pdf", _pdf(*[TEXT_PAGE] * 3), "application/pdf")
    assert _reason("pdf", _pdf(*[TEXT_PAGE] * 4), "application/pdf") == "too_large"
    assert MAX_PDF_PAGES == 1_000


def test_without_pypdf_a_pdf_needs_it(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "pypdf", None)

    assert _reason("pdf", _pdf(TEXT_PAGE), "application/pdf") == "needs_pypdf"
    assert documents.pdf_reader_version() is None


def test_the_time_budget_is_checked_between_pages_and_parts(monkeypatch) -> None:
    clock = iter(range(0, 1_000, 6))
    monkeypatch.setattr(documents.time, "monotonic", lambda: next(clock))

    assert _reason("pdf", _pdf(*[TEXT_PAGE] * 3), "application/pdf") == "too_slow"
    docx_mime = (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    data = _docx("a", extra={"word/header1.xml": "b", "word/footer1.xml": "c"})
    assert _reason("docx", data, docx_mime) == "too_slow"


DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def test_docx_text_comes_from_the_body_headers_footers_notes_and_comments() -> None:
    data = _docx(
        "Birinci paragraf",
        "Ikinci paragraf",
        extra={
            "word/header1.xml": "Ust bilgi",
            "word/footer1.xml": "Alt bilgi",
            "word/footnotes.xml": "Dipnot",
            "word/endnotes.xml": "Son not",
            "word/comments.xml": "Yorum",
            "word/styles.xml": "not text",
        },
    )

    text = _text_of("docx", data, DOCX)

    assert text.split("\n")[:2] == ["Birinci paragraf", "Ikinci paragraf"]
    for piece in ("Ust bilgi", "Alt bilgi", "Dipnot", "Son not", "Yorum"):
        assert piece in text
    assert "not text" not in text


def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_unreadable_docx_files_name_their_reason(monkeypatch) -> None:
    doctype = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>'
    assert _reason("docx", _zip({"word/document.xml": doctype}), DOCX) == "corrupt"
    assert _reason("docx", _zip({"other.xml": b"<x/>"}), DOCX) == "corrupt"
    assert _reason("docx", b"PK\x03\x04 not a zip", DOCX) == "corrupt"
    assert _reason("docx", _zip({"word/document.xml": b"<x"}), DOCX) == "corrupt"

    many = {f"f{index}": b"" for index in range(documents.MAX_ZIP_ENTRIES - 1)}
    assert _text_of("docx", _zip({**many, "word/document.xml": b"<x/>"}), DOCX) == ""
    many["one-more"] = b""
    assert (
        _reason("docx", _zip({**many, "word/document.xml": b"<x/>"}), DOCX)
        == "too_large"
    )

    monkeypatch.setattr(documents, "MAX_DOCX_PART_BYTES", 100)
    assert (
        _text_of("docx", _zip({"word/document.xml": b"<x/>" + b" " * 96}), DOCX) == ""
    )
    assert (
        _reason("docx", _zip({"word/document.xml": b"<x/>" + b" " * 97}), DOCX)
        == "too_large"
    )
    monkeypatch.setattr(documents, "MAX_DOCX_TOTAL_BYTES", 150)
    entries = {"word/document.xml": b"<x/>", "a": b" " * 80, "b": b" " * 80}
    assert _reason("docx", _zip(entries), DOCX) == "too_large"


def test_a_part_that_lies_about_its_size_is_corrupt() -> None:
    honest = _zip({"word/document.xml": _docx_document("words " * 50)})
    # The central directory says the part is 10 bytes long.
    directory = honest.rindex(b"PK\x01\x02")
    lying = bytearray(honest)
    lying[directory + 24 : directory + 28] = (10).to_bytes(4, "little")

    assert _reason("docx", bytes(lying), DOCX) == "corrupt"


def _docx_document(text: str) -> bytes:
    return (
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"
    ).encode()


def test_text_files_are_strict_utf8_without_a_bom() -> None:
    assert _text_of("text", "﻿Merhaba dünya".encode(), "text/plain") == "Merhaba dünya"
    assert _text_of("text", b'{"a": 1}', "application/json") == '{"a": 1}'
    assert _reason("text", b"Merhaba \xff", "text/plain") == "corrupt"


def test_document_size_bounds(monkeypatch) -> None:
    assert _text_of("text", b"x" * MAX_DOCUMENT_CHARS, "text/plain")
    assert _reason("text", b"x" * (MAX_DOCUMENT_CHARS + 1), "text/plain") == "too_large"
    part, data = _part("text", b"x" * 10, "text/plain")
    monkeypatch.setattr(documents, "MAX_DECODED_BYTES", 10)
    assert extract_text(part, data)
    monkeypatch.setattr(documents, "MAX_DECODED_BYTES", 9)
    with pytest.raises(Unscannable, match="too_large"):
        extract_text(part, data)


def test_url_and_file_id_documents_are_not_inline() -> None:
    (part,) = classify_media(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "input_file", "file_id": "f", "filename": "a.pdf"}
                    ],
                }
            ]
        }
    )

    with pytest.raises(Unscannable, match="not_inline"):
        extract_text(part, None)


# Each protocol shape, built around one document's base64.
SHAPES = {
    "anthropic": lambda data, mime: {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "title": "Rapor",
                        "context": "Ekim",
                        "citations": {"enabled": True},
                        "cache_control": {"type": "ephemeral"},
                        "source": {"type": "base64", "media_type": mime, "data": data},
                    }
                ],
            }
        ]
    },
    "chat": lambda data, mime: {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "file",
                        "file": {
                            "filename": "rapor.pdf",
                            "file_data": f"data:{mime};base64,{data}",
                        },
                    }
                ],
            }
        ]
    },
    "responses": lambda data, mime: {
        "input": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_file",
                        "filename": "rapor.pdf",
                        "file_data": f"data:{mime};base64,{data}",
                    }
                ],
            }
        ]
    },
    "gemini": lambda data, mime: {
        "contents": [
            {
                "role": "user",
                "parts": [{"inlineData": {"mimeType": mime, "data": data}}],
            }
        ]
    },
}


def _first_part(shape: str, payload: dict) -> dict:
    turn = payload[
        "contents"
        if shape == "gemini"
        else "input"
        if shape == "responses"
        else "messages"
    ][0]
    return turn["parts" if shape == "gemini" else "content"][0]


def _scrub(payload: dict, **values):
    report = DocumentReport()
    unmasked: dict[str, str] = {}
    safe, mapping = scrub_payload(
        payload,
        values.pop("actions", DEFAULT_ACTIONS),
        PIIScrubberService(),
        report=report,
        unmasked=unmasked,
        **values,
    )
    return safe, mapping, report, unmasked


EMAIL_PDF = _pdf("Iletisim: ayse.yilmaz@example.com adresine yazin.")


@pytest.mark.parametrize("shape", SHAPES)
def test_a_clean_document_is_forwarded_unchanged(shape) -> None:
    payload = SHAPES[shape](_b64(_pdf(TEXT_PAGE)), "application/pdf")

    safe, _, report, _ = _scrub(payload, documents="scan")

    assert _first_part(shape, safe) == _first_part(shape, payload)
    assert (report.scanned, report.native, report.converted) == (1, 1, 0)


@pytest.mark.parametrize("shape", SHAPES)
def test_a_masked_value_in_a_document_stops_the_request_under_scan(shape) -> None:
    payload = SHAPES[shape](_b64(EMAIL_PDF), "application/pdf")

    with pytest.raises(HTTPException) as stopped:
        _scrub(payload, documents="scan")

    assert stopped.value.status_code == 400
    assert stopped.value.detail["code"] == "PII_BLOCKED"
    assert stopped.value.detail["reason_code"] == "DOCUMENT_MASKING_REQUIRED"
    assert "EMAIL_ADDRESS" in stopped.value.detail["message"]
    assert "conversion" in stopped.value.detail["message"]
    assert "ayse" not in stopped.value.detail["message"]


def test_a_secret_in_a_document_stops_with_secret_blocked() -> None:
    payload = SHAPES["gemini"](
        _b64(_pdf("Anahtar: sk-proj-" + "0" * 32)), "application/pdf"
    )

    with pytest.raises(HTTPException) as stopped:
        _scrub(payload, documents="scan")

    assert stopped.value.detail["code"] == "SECRET_BLOCKED"


def test_a_blocked_type_in_a_document_takes_the_block_path() -> None:
    payload = SHAPES["anthropic"](_b64(EMAIL_PDF), "application/pdf")
    actions = {**DEFAULT_ACTIONS, "EMAIL_ADDRESS": "block"}

    safe, _, report, unmasked = _scrub(payload, documents="scan", actions=actions)

    assert set(unmasked.values()) == {"EMAIL_ADDRESS"}
    assert _first_part("anthropic", safe) == _first_part("anthropic", payload)
    assert report.entities == {"EMAIL_ADDRESS": 1}


def test_monitored_values_in_a_document_pass_and_are_counted() -> None:
    payload = SHAPES["chat"](_b64(EMAIL_PDF), "application/pdf")
    actions = {**DEFAULT_ACTIONS, "EMAIL_ADDRESS": "monitor"}

    safe, mapping, report, unmasked = _scrub(payload, documents="scan", actions=actions)

    assert _first_part("chat", safe) == _first_part("chat", payload)
    assert mapping == {} and set(unmasked.values()) == {"EMAIL_ADDRESS"}
    assert report.native == 1 and report.entities == {"EMAIL_ADDRESS": 1}


@pytest.mark.parametrize("shape", SHAPES)
def test_scan_and_convert_sends_the_masked_text(shape) -> None:
    payload = SHAPES[shape](_b64(EMAIL_PDF), "application/pdf")

    safe, mapping, report, _ = _scrub(payload, documents="scan_and_convert")

    [placeholder] = mapping
    assert mapping[placeholder] == "ayse.yilmaz@example.com"
    part = _first_part(shape, safe)
    if shape == "anthropic":
        assert part["source"]["type"] == "text"
        assert part["source"]["media_type"] == "text/plain"
        assert placeholder in part["source"]["data"]
        for kept in ("title", "context", "citations", "cache_control"):
            assert part[kept] == _first_part(shape, payload)[kept]
    elif shape == "gemini":
        assert set(part) == {"text"} and placeholder in part["text"]
    else:
        assert part["type"] == ("text" if shape == "chat" else "input_text")
        assert part["text"].startswith("[document: rapor.pdf]\n")
        assert placeholder in part["text"]
    assert "ayse" not in str(safe)
    assert report.converted == 1
    [entry] = report.transforms
    assert entry["id"] == "document_text" and entry["version"] == 1
    assert entry["after_chars"] < entry["before_chars"]
    assert entry["reader"].startswith("pypdf ")


def test_by_provider_converts_only_the_kinds_named() -> None:
    pdf_payload = SHAPES["gemini"](_b64(_pdf(TEXT_PAGE)), "application/pdf")

    native, _, kept, _ = _scrub(
        pdf_payload, documents="scan", convert_clean=frozenset({"docx"})
    )
    text, _, converted, _ = _scrub(
        pdf_payload, documents="scan", convert_clean=frozenset({"docx", "pdf"})
    )

    assert _first_part("gemini", native) == _first_part("gemini", pdf_payload)
    assert kept.native == 1 and kept.transforms == []
    assert "Rapor hazir" in _first_part("gemini", text)["text"]
    assert converted.converted == 1


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (_pdf(TEXT_PAGE, encrypt=True), "encrypted"),
        (_pdf(""), "no_text_layer"),
        (b"%PDF-1.4 broken", "corrupt"),
    ],
)
def test_an_unscannable_document_follows_media_inputs(data, reason) -> None:
    payload = SHAPES["anthropic"](_b64(data), "application/pdf")

    with pytest.raises(HTTPException) as refused:
        _scrub(payload, documents="scan")
    safe, _, report, _ = _scrub(payload, documents="scan", media_inputs="allow")

    assert refused.value.detail["code"] == "DOCUMENT_UNSCANNABLE"
    assert reason in refused.value.detail["message"]
    assert _first_part("anthropic", safe) == _first_part("anthropic", payload)
    assert report.unscannable == {reason: 1} and report.scanned == 0


def test_documents_as_media_keep_the_media_refusal() -> None:
    payload = SHAPES["chat"](_b64(_pdf(TEXT_PAGE)), "application/pdf")

    with pytest.raises(HTTPException) as refused:
        _scrub(payload)

    assert refused.value.detail["code"] == "PRIVACY_POLICY_BLOCKED"


def test_a_request_reads_at_most_four_million_characters(monkeypatch) -> None:
    monkeypatch.setattr(documents, "MAX_DOCUMENT_CHARS", 10)
    monkeypatch.setattr("shim.gateway.pipeline.privacy.MAX_REQUEST_CHARS", 25)
    texts = [
        {"inlineData": {"mimeType": "text/plain", "data": _b64(b"x" * 10)}}
        for _ in range(3)
    ]
    payload = {"contents": [{"role": "user", "parts": texts}]}

    with pytest.raises(HTTPException) as refused:
        _scrub(payload, documents="scan")
    _, _, report, _ = _scrub(payload, documents="scan", media_inputs="allow")

    assert "too_large" in refused.value.detail["message"]
    assert report.scanned == 2 and report.unscannable == {"too_large": 1}
