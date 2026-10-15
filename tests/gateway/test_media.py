import base64
import struct

import pytest

from shim.gateway.media import (
    IMAGE_MAX_TOKENS,
    IMAGE_UNKNOWN_TOKENS,
    MediaPart,
    PDF_MAX_PAGES,
    classify_media,
    image_dimensions,
    media_tokens,
    pdf_page_count,
    value_at,
)


def _png(width: int, height: int) -> bytes:
    return (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR"
        + struct.pack(">II", width, height)
        + b"\x08\x02\x00\x00\x00"
    )


def _jpeg(width: int, height: int) -> bytes:
    app0 = b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    sof = (
        b"\xff\xc0\x00\x11\x08" + struct.pack(">HH", height, width) + b"\x03" + bytes(9)
    )
    return b"\xff\xd8" + app0 + sof


def _gif(width: int, height: int) -> bytes:
    return b"GIF89a" + struct.pack("<HH", width, height)


def _webp(chunk: bytes, body: bytes) -> bytes:
    return b"RIFF\x00\x00\x00\x00WEBP" + chunk + struct.pack("<I", len(body)) + body


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _data_url(mime: str, data: bytes) -> str:
    return f"data:{mime};base64,{_b64(data)}"


PNG = _png(4000, 3000)
PDF = b"%PDF-1.4\n1 0 obj<</Type /Pages>>\n2 0 obj<</Type /Page>>\n3 0 obj<</Type/Page>>\n"


def _chat(*parts: object) -> dict[str, object]:
    return {"model": "m", "messages": [{"role": "user", "content": list(parts)}]}


def _responses(*parts: object) -> dict[str, object]:
    return {"model": "m", "input": [{"role": "user", "content": list(parts)}]}


def _gemini(*parts: object) -> dict[str, object]:
    return {"contents": [{"role": "user", "parts": list(parts)}]}


def _one(payload: dict[str, object]) -> MediaPart:
    (part,) = classify_media(payload)
    return part


@pytest.mark.parametrize(
    ("payload", "kind", "source", "data"),
    [
        (
            _chat(
                {
                    "type": "image_url",
                    "image_url": {"url": _data_url("image/png", PNG)},
                }
            ),
            "image",
            "inline",
            ("image_url", "url"),
        ),
        (
            _chat({"type": "image_url", "image_url": {"url": "https://x.test/a.png"}}),
            "image",
            "url",
            None,
        ),
        (
            _chat(
                {
                    "type": "file",
                    "file": {
                        "file_data": _data_url("application/pdf", PDF),
                        "filename": "a.pdf",
                    },
                }
            ),
            "pdf",
            "inline",
            ("file", "file_data"),
        ),
        (
            _chat({"type": "file", "file": {"file_id": "file-1"}}),
            "other",
            "file_id",
            None,
        ),
        (
            _chat(
                {
                    "type": "input_audio",
                    "input_audio": {"data": "AAAA", "format": "wav"},
                }
            ),
            "audio",
            "inline",
            ("input_audio", "data"),
        ),
        (
            _responses(
                {"type": "input_image", "image_url": _data_url("image/png", PNG)}
            ),
            "image",
            "inline",
            ("image_url",),
        ),
        (
            _responses(
                {
                    "type": "input_file",
                    "file_data": _data_url("application/pdf", PDF),
                    "filename": "a.pdf",
                }
            ),
            "pdf",
            "inline",
            ("file_data",),
        ),
        (
            _responses({"type": "input_file", "file_url": "https://x.test/a"}),
            "other",
            "url",
            None,
        ),
        (
            _responses(
                {"type": "input_file", "file_id": "file-1", "filename": "r.csv"}
            ),
            "text",
            "file_id",
            None,
        ),
        (
            {
                "input": [
                    {
                        "type": "computer_call_output",
                        "call_id": "c1",
                        "output": {
                            "type": "computer_screenshot",
                            "image_url": _data_url("image/png", PNG),
                        },
                    }
                ]
            },
            "image",
            "inline",
            ("image_url",),
        ),
        (
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "container_upload", "file_id": "file-1"}],
                    }
                ]
            },
            "other",
            "file_id",
            None,
        ),
        (
            {
                "tools": [
                    {
                        "type": "image_generation",
                        "input_image_mask": {"image_url": _data_url("image/png", PNG)},
                    }
                ]
            },
            "image",
            "inline",
            ("input_image_mask", "image_url"),
        ),
        (
            {
                "input": [
                    {
                        "type": "image_generation_call",
                        "id": "ig_1",
                        "result": _b64(PNG),
                        "status": "completed",
                    }
                ]
            },
            "image",
            "inline",
            ("result",),
        ),
        (
            _chat(
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": _b64(PNG),
                    },
                }
            ),
            "image",
            "inline",
            ("source", "data"),
        ),
        (
            _chat(
                {
                    "type": "document",
                    "source": {
                        "type": "base64",
                        "media_type": "application/pdf",
                        "data": _b64(PDF),
                    },
                }
            ),
            "pdf",
            "inline",
            ("source", "data"),
        ),
        (
            _chat({"type": "document", "source": {"type": "url", "url": "https://x"}}),
            "pdf",
            "url",
            None,
        ),
        (
            _chat({"type": "image", "source": {"type": "file", "file_id": "file-1"}}),
            "image",
            "file_id",
            None,
        ),
        (
            _chat(
                {"type": "document", "source": {"type": "file", "file_id": "file-1"}}
            ),
            "pdf",
            "file_id",
            None,
        ),
        (
            _gemini({"inlineData": {"mimeType": "image/png", "data": _b64(PNG)}}),
            "image",
            "inline",
            ("inlineData", "data"),
        ),
        (
            _gemini(
                {"fileData": {"mimeType": "application/pdf", "fileUri": "gs://b/a"}}
            ),
            "pdf",
            "url",
            None,
        ),
    ],
)
def test_every_media_shape_is_classified(payload, kind, source, data) -> None:
    part = _one(payload)

    assert (part.kind, part.source) == (kind, source)
    if data is None:
        assert part.data_path is None and part.decoded_bytes is None
    else:
        assert part.data_path == (*part.path, *data)
        assert isinstance(value_at(payload, part.data_path), str)
        assert part.decoded_bytes is not None and part.decoded_bytes > 0


def test_a_part_records_its_path_mime_size_and_dimensions() -> None:
    payload = _chat(
        {"type": "text", "text": "look"},
        {"type": "image_url", "image_url": {"url": _data_url("image/png", PNG)}},
    )

    part = _one(payload)

    assert part.path == ("messages", 0, "content", 1)
    assert part.mime == "image/png"
    assert part.decoded_bytes == len(PNG)
    assert part.dimensions == (4000, 3000)


@pytest.mark.parametrize(
    ("payload", "media"),
    [
        # Every part the privacy stage refused before the classifier existed.
        (_chat({"type": "image_url", "image_url": "https://x.test/a.png"}), True),
        (_chat({"type": "input_audio", "input_audio": {"data": "AA"}}), True),
        (_chat({"type": "file", "file": {"file_data": "AA"}}), True),
        (_chat({"type": "input_file", "file_id": "file_123"}), True),
        (_chat({"type": "image", "source": {"type": "file", "file_id": "f"}}), True),
        (
            {
                "input": [
                    {
                        "type": "function_call_output",
                        "call_id": "c",
                        "output": [{"type": "file", "file": {"file_data": "AA"}}],
                    }
                ]
            },
            True,
        ),
        (
            _chat(
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "lookup",
                    "input": {
                        "type": "image",
                        "source": {"type": "base64", "data": "A"},
                    },
                }
            ),
            True,
        ),
        (
            {
                "tools": [
                    {"type": "image_generation", "input_image_mask": {"file_id": "f"}}
                ]
            },
            True,
        ),
        # Text the privacy stage reads, and tool data without its media field.
        (_chat({"type": "document", "source": {"type": "text", "data": "x"}}), False),
        (
            _chat({"type": "document", "source": {"type": "content", "content": []}}),
            False,
        ),
        (
            {
                "input": [
                    {"type": {"kind": "record"}, "text": "safe"},
                    {
                        "type": "function_call_output",
                        "call_id": "c",
                        "output": {"type": "image", "label": "diagram"},
                    },
                ],
                "tools": [
                    {
                        "type": "function",
                        "parameters": {
                            "type": "file",
                            "properties": {"inlineData": {"type": "string"}},
                        },
                    }
                ],
            },
            False,
        ),
        (
            {
                "input": [
                    {
                        "type": "image_generation_call",
                        "id": "ig",
                        "result": None,
                        "status": "in_progress",
                    }
                ]
            },
            False,
        ),
        # Outside content, a typed media object is a protocol value.
        ({"metadata": {"type": "image_url", "image_url": "x"}}, False),
        ({"model": "image", "messages": [{"role": "user", "content": "file"}]}, False),
    ],
)
def test_the_classifier_finds_exactly_what_privacy_refused(payload, media) -> None:
    assert bool(classify_media(payload)) is media


def test_parts_are_listed_in_payload_order_and_never_nested() -> None:
    payload = _gemini(
        {"inlineData": {"mimeType": "image/png", "data": _b64(PNG)}},
        {"text": "between"},
        {"fileData": {"mimeType": "image/png", "fileUri": "gs://b/a"}},
    )

    parts = classify_media(payload)

    assert [part.path for part in parts] == [
        ("contents", 0, "parts", 0),
        ("contents", 0, "parts", 2),
    ]


@pytest.mark.parametrize(
    ("declared", "data", "kind"),
    [
        ("image/png", PNG, "image"),
        ("image/png", PDF, "other"),
        ("application/pdf", PNG, "other"),
        ("application/octet-stream", PDF, "pdf"),
        ("application/zip", b"PK\x03\x04rest", "other"),
        ("text/plain", b"plain words", "text"),
        ("text/plain", PDF, "other"),
    ],
)
def test_the_first_bytes_must_agree_with_the_declared_type(
    declared, data, kind
) -> None:
    payload = _gemini({"inlineData": {"mimeType": declared, "data": _b64(data)}})

    assert _one(payload).kind == kind


def test_a_filename_extension_votes_with_the_other_evidence() -> None:
    def kind(filename: str, data: bytes) -> str:
        return _one(
            _chat(
                {
                    "type": "file",
                    "file": {"file_data": _b64(data), "filename": filename},
                }
            )
        ).kind

    assert kind("report.pdf", PDF) == "pdf"
    assert kind("report.docx", b"PK\x03\x04rest") == "docx"
    assert kind("photo.png", PDF) == "other"


@pytest.mark.parametrize(
    ("data", "size"),
    [
        (_png(4000, 3000), (4000, 3000)),
        (_jpeg(640, 480), (640, 480)),
        (_gif(32, 16), (32, 16)),
        (
            _webp(b"VP8 ", b"\x00\x00\x00\x9d\x01\x2a" + struct.pack("<HH", 300, 200)),
            (300, 200),
        ),
        (
            _webp(b"VP8L", b"\x2f" + struct.pack("<I", (99 << 14) | 199)),
            (200, 100),
        ),
        (
            _webp(
                b"VP8X",
                bytes(4) + (799).to_bytes(3, "little") + (599).to_bytes(3, "little"),
            ),
            (800, 600),
        ),
    ],
)
def test_image_dimensions_read_each_header(data, size) -> None:
    assert image_dimensions(data) == size


@pytest.mark.parametrize(
    "data",
    [
        _png(4000, 3000)[:20],
        _jpeg(640, 480)[:22],
        _gif(32, 16)[:8],
        _webp(b"VP8X", bytes(4))[:26],
        _png(0, 3000),
        b"%PDF-1.4",
        b"",
        b"\xff\xd8\x00\x00garbage",
    ],
)
def test_truncated_or_unknown_headers_have_no_dimensions(data) -> None:
    assert image_dimensions(data) is None


def test_a_jpeg_frame_after_large_segments_is_found() -> None:
    exif = b"\xff\xe1" + struct.pack(">H", 30_002) + bytes(30_000)
    data = b"\xff\xd8" + exif + _jpeg(1920, 1080)[2:]

    assert image_dimensions(data) == (1920, 1080)
    part = _one(_gemini({"inlineData": {"mimeType": "image/jpeg", "data": _b64(data)}}))
    assert part.dimensions == (1920, 1080)


def test_pdf_pages_are_counted_up_to_the_cap() -> None:
    assert pdf_page_count(_b64(PDF)) == 2
    assert pdf_page_count(_data_url("application/pdf", PDF)) == 2
    assert pdf_page_count(_b64(b"%PDF-1.7 compressed objects only")) is None
    assert pdf_page_count("not base64 !!!") is None
    many = b"%PDF-1.4" + b"<</Type /Page>>" * (PDF_MAX_PAGES + 5)
    assert pdf_page_count(_b64(many)) == PDF_MAX_PAGES


def test_part_tokens_follow_the_published_estimates() -> None:
    def part(kind, source="inline", decoded=4_000, dimensions=None) -> MediaPart:
        return MediaPart(("p",), kind, source, None, None, decoded, dimensions)

    assert media_tokens(part("image", dimensions=(4000, 3000))) == IMAGE_MAX_TOKENS
    assert media_tokens(part("image", dimensions=(512, 512))) == 19 * 19
    assert media_tokens(part("image")) == IMAGE_UNKNOWN_TOKENS
    assert (
        media_tokens(part("image", source="url", decoded=None)) == IMAGE_UNKNOWN_TOKENS
    )
    assert media_tokens(part("pdf"), pdf_pages=3) == 9_000
    assert media_tokens(part("pdf")) == 1_000
    assert media_tokens(part("pdf", source="file_id", decoded=None)) == 30_000
    assert media_tokens(part("docx")) == 1_000
    assert media_tokens(part("text")) == 1_000
    for kind in ("audio", "video", "other"):
        assert media_tokens(part(kind)) is None


def test_an_image_costs_what_its_model_is_billed() -> None:
    image = MediaPart(("p",), "image", "inline", None, None, 4_000, (1024, 1024))

    # gpt-4o-mini bills 33 times gpt-4o's tile price; 1,369 tiles were reserved before.
    assert media_tokens(image, provider="openai", model="gpt-4o-mini") == 25_501
    assert media_tokens(image, provider="openai", model="gpt-4o") == 765
    assert media_tokens(image, provider="openai", model="gpt-5-nano") == 37 * 37
