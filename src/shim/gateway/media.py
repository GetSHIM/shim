"""Images and files in a provider payload: where they are, what they are, how big."""

from __future__ import annotations

import binascii
from collections.abc import Mapping
from dataclasses import dataclass
import math
import re
from typing import Any, Literal

from shim.privacy.policies import (
    DEEP_PRIVACY_FIELDS,
    OPAQUE_MEDIA_FIELDS,
    OPAQUE_MEDIA_TYPE_FIELDS,
    OPAQUE_PROTOCOL_FIELDS_BY_TYPE,
    PRIVACY_BEARING_FIELDS,
    is_protocol_field,
)

MediaKind = Literal["image", "pdf", "docx", "text", "audio", "video", "other"]
Path = tuple[str | int, ...]

# Words one of which every media part's JSON carries; text without them is never walked.
MEDIA_MARKERS = re.compile(
    "image|file|document|inlineData|inline_data|fileData|file_data|input_audio"
    "|computer_screenshot|container_upload|input_image_mask"
)

# Estimates as of 2026-10-14, before the provider counts: images are read in 28-pixel
# tiles up to a cap, as the vision pages of OpenAI (platform.openai.com/docs/guides/images-vision),
# Anthropic (docs.anthropic.com/en/docs/build-with-claude/vision) and Gemini
# (ai.google.dev/gemini-api/docs/image-understanding) describe; a PDF page is read as
# text plus an image (docs.anthropic.com/en/docs/build-with-claude/pdf-support).
IMAGE_TILE = 28
IMAGE_MAX_TOKENS = 4_784
IMAGE_UNKNOWN_TOKENS = 1_600
PDF_PAGE_TOKENS = 3_000
PDF_UNKNOWN_TOKENS = 30_000
PDF_MAX_PAGES = 1_000
_HEADER_BYTES = 65_536

_TYPE_KINDS: Mapping[str, MediaKind] = {
    "computer_screenshot": "image",
    "document": "pdf",
    "image": "image",
    "image_generation": "image",
    "image_generation_call": "image",
    "image_url": "image",
    "input_audio": "audio",
    "input_image": "image",
}
_MIME_KINDS: Mapping[str, MediaKind] = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
}
_MIME_FAMILIES: Mapping[str, MediaKind] = {
    "image/": "image",
    "audio/": "audio",
    "video/": "video",
    "text/": "text",
}
_EXTENSION_KINDS: Mapping[str, MediaKind] = {
    "png": "image",
    "jpg": "image",
    "jpeg": "image",
    "gif": "image",
    "webp": "image",
    "pdf": "pdf",
    "docx": "docx",
    "txt": "text",
    "md": "text",
    "csv": "text",
    "mp3": "audio",
    "wav": "audio",
    "mp4": "video",
}
# The first bytes of each kind; a ZIP is taken for a Word file.
_SIGNATURES: tuple[tuple[bytes, MediaKind], ...] = (
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "docx"),
    (b"\x89PNG\r\n\x1a\n", "image"),
    (b"\xff\xd8\xff", "image"),
    (b"GIF87a", "image"),
    (b"GIF89a", "image"),
)
# Where a part keeps its inline data or its link, relative to the part.
_DATA_FIELDS: tuple[tuple[str, ...], ...] = (
    ("source", "data"),
    ("inlineData", "data"),
    ("inline_data", "data"),
    ("file_data",),
    ("file", "file_data"),
    ("input_audio", "data"),
    ("result",),
    ("image_url",),
    ("image_url", "url"),
    ("input_image_mask", "image_url"),
)
_FILE_ID_FIELDS: tuple[tuple[str, ...], ...] = (
    ("file_id",),
    ("source", "file_id"),
    ("file", "file_id"),
    ("input_image_mask", "file_id"),
)
_URL_FIELDS: tuple[tuple[str, ...], ...] = (
    ("source", "url"),
    ("file_url",),
    ("fileData", "fileUri"),
    ("file_data", "file_uri"),
)
_MIME_FIELDS: tuple[tuple[str, ...], ...] = (
    ("source", "media_type"),
    ("inlineData", "mimeType"),
    ("inline_data", "mime_type"),
    ("fileData", "mimeType"),
    ("file_data", "mime_type"),
)
_PDF_PAGE = re.compile(rb"/Type\s*/Page(?![A-Za-z])")


@dataclass(frozen=True, slots=True)
class MediaPart:
    """One image or file of a request; never its content."""

    path: Path
    kind: MediaKind
    source: Literal["inline", "url", "file_id"]
    mime: str | None
    # The base64 or data-URL string of an inline part.
    data_path: Path | None
    decoded_bytes: int | None
    # Width and height from an inline image's header.
    dimensions: tuple[int, int] | None = None


def is_media(value: Mapping[str, Any], *, deep: bool) -> bool:
    """Whether a payload object is a part the privacy stage cannot read.

    In tool data (`deep`) a typed part counts only with its media field set.
    """
    media_type = value.get("type")
    media_fields = (
        OPAQUE_MEDIA_TYPE_FIELDS.get(media_type)
        if isinstance(media_type, str)
        else None
    )
    requires_field = deep or media_type == "image_generation_call"
    if media_fields is not None and (
        not requires_field
        or any(value.get(field) is not None for field in media_fields)
    ):
        return True
    if isinstance(media_type, str) and media_type in {"document", "image"}:
        source = value.get("source")
        source_type = source.get("type") if isinstance(source, Mapping) else None
        if isinstance(source_type, str) and source_type in {"base64", "url"}:
            return True
    return any(value.get(field) is not None for field in OPAQUE_MEDIA_FIELDS)


def classify_media(payload: Mapping[str, Any]) -> tuple[MediaPart, ...]:
    """Every media part, found where the privacy stage's walk would refuse it."""
    parts: list[MediaPart] = []

    # The same descent as the privacy visitor (`scrub_payload`), which this must match.
    def walk(
        value: Any, path: Path, content: bool, deep: bool, hint: MediaKind | None
    ) -> None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, (*path, index), content, deep, None)
            return
        if not isinstance(value, Mapping):
            return
        value_type = value.get("type")
        if (content or value_type == "image_generation") and is_media(value, deep=deep):
            parts.append(_describe(value, path, hint))
            return
        # An Anthropic file source is the part; its parent names the kind.
        child_hint = (
            _TYPE_KINDS[value_type] if value_type in ("image", "document") else None
        )
        for key, item in value.items():
            at = (*path, key)
            if deep:
                walk(item, at, content, True, None)
            elif key == "model" or is_protocol_field(key):
                continue
            elif isinstance(
                value_type, str
            ) and key in OPAQUE_PROTOCOL_FIELDS_BY_TYPE.get(value_type, ()):
                continue
            elif key == "input":
                walk(item, at, True, content, None)
            elif key in DEEP_PRIVACY_FIELDS:
                walk(item, at, content, True, None)
            else:
                walk(
                    item,
                    at,
                    content or key in PRIVACY_BEARING_FIELDS,
                    False,
                    child_hint if key == "source" else None,
                )

    walk(payload, (), False, False, None)
    return tuple(parts)


def value_at(payload: Any, path: Path) -> Any:
    for step in path:
        payload = payload[step]
    return payload


def image_dimensions(data: bytes) -> tuple[int, int] | None:
    """Width and height from a PNG, JPEG, GIF or WEBP header; None when unreadable."""
    if data.startswith(b"\x89PNG\r\n\x1a\n") and data[12:16] == b"IHDR":
        return _size(_number(data, 16, 4, "big"), _number(data, 20, 4, "big"))
    if data[:6] in {b"GIF87a", b"GIF89a"}:
        return _size(_number(data, 6, 2, "little"), _number(data, 8, 2, "little"))
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return _webp(data)
    if data.startswith(b"\xff\xd8"):
        return _jpeg(data)
    return None


def media_tokens(part: MediaPart, pdf_pages: int | None = None) -> int | None:
    """A part's estimated input tokens; None when it is measured as text, by its bytes."""
    if part.kind == "image":
        if part.dimensions is None:
            return IMAGE_UNKNOWN_TOKENS
        width, height = part.dimensions
        return min(
            math.ceil(width / IMAGE_TILE) * math.ceil(height / IMAGE_TILE),
            IMAGE_MAX_TOKENS,
        )
    if part.kind == "pdf":
        if part.source != "inline":
            return PDF_UNKNOWN_TOKENS
        if pdf_pages:
            return pdf_pages * PDF_PAGE_TOKENS
        return (part.decoded_bytes or 0) // 4
    if part.kind in {"docx", "text"}:
        return (part.decoded_bytes or 0) // 4
    return None


def pdf_page_count(data: str) -> int | None:
    """Page objects in an inline PDF, at most `PDF_MAX_PAGES`; None when none are found."""
    _, encoded = split_data_url(data)
    try:
        decoded = binascii.a2b_base64(encoded)
    except ValueError:
        return None
    pages = 0
    for _ in _PDF_PAGE.finditer(decoded):
        pages += 1
        if pages == PDF_MAX_PAGES:
            break
    return pages or None


def split_data_url(data: str) -> tuple[str | None, str]:
    """The declared MIME type of a data URL and its base64; raw base64 has none."""
    if not data.startswith("data:"):
        return None, data
    header, _, encoded = data.partition(",")
    return header[5:].split(";")[0].lower() or None, encoded


def _describe(
    value: Mapping[str, Any], path: Path, hint: MediaKind | None
) -> MediaPart:
    data_path: Path | None = None
    data: str | None = None
    source: Literal["inline", "url", "file_id"] | None = None
    for relative in _DATA_FIELDS:
        found = _get(value, relative)
        if isinstance(found, str):
            if relative[-1] in {"image_url", "url"} and not found.startswith("data:"):
                source = "url"
                continue
            data_path, data, source = (*path, *relative), found, "inline"
            break
    if source is None:
        source = (
            "file_id"
            if any(isinstance(_get(value, field), str) for field in _FILE_ID_FIELDS)
            else "url"
            if any(isinstance(_get(value, field), str) for field in _URL_FIELDS)
            else "inline"
        )
    mime = next(
        (
            found.lower()
            for field in _MIME_FIELDS
            if isinstance(found := _get(value, field), str)
        ),
        None,
    )
    decoded_bytes = head = None
    if data is not None:
        declared, encoded = split_data_url(data)
        mime = declared or mime
        decoded_bytes = len(encoded.rstrip("=")) * 3 // 4
        head = _decoded_head(encoded, 16)
    value_type = value.get("type")
    filename = _get(value, ("file", "filename")) or value.get("filename")
    votes = {
        vote
        for vote in (
            (_TYPE_KINDS.get(value_type) if isinstance(value_type, str) else None)
            or hint,
            _mime_kind(mime),
            _EXTENSION_KINDS.get(filename.rpartition(".")[2].lower())
            if isinstance(filename, str) and "." in filename
            else None,
            _signature_kind(head) if head else None,
        )
        if vote is not None
    }
    kind: MediaKind = votes.pop() if len(votes) == 1 else "other"
    dimensions = (
        image_dimensions(_decoded_head(split_data_url(data)[1], _HEADER_BYTES))
        if kind == "image" and data is not None
        else None
    )
    return MediaPart(path, kind, source, mime, data_path, decoded_bytes, dimensions)


def _get(value: Any, path: tuple[str, ...]) -> Any:
    for step in path:
        if not isinstance(value, Mapping):
            return None
        value = value.get(step)
    return value


def _mime_kind(mime: str | None) -> MediaKind | None:
    if mime is None or mime == "application/octet-stream":
        return None
    if mime in _MIME_KINDS:
        return _MIME_KINDS[mime]
    # A declared type that is none of these disagrees with any other evidence.
    return next(
        (kind for prefix, kind in _MIME_FAMILIES.items() if mime.startswith(prefix)),
        "other",
    )


def _signature_kind(head: bytes) -> MediaKind | None:
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image"
    return next((kind for magic, kind in _SIGNATURES if head.startswith(magic)), None)


def _decoded_head(encoded: str, size: int) -> bytes:
    wanted = (size + 2) // 3 * 4
    # Line breaks inside base64 are dropped first, then whole quanta are decoded.
    chunk = "".join(encoded[: wanted * 2].split())[:wanted]
    try:
        return binascii.a2b_base64(chunk[: len(chunk) // 4 * 4])
    except ValueError:
        return b""


def _number(
    data: bytes, start: int, size: int, order: Literal["big", "little"]
) -> int | None:
    chunk = data[start : start + size]
    return int.from_bytes(chunk, order) if len(chunk) == size else None


def _size(width: int | None, height: int | None) -> tuple[int, int] | None:
    return (width, height) if width and height else None


def _webp(data: bytes) -> tuple[int, int] | None:
    chunk = data[12:16]
    if chunk == b"VP8 " and data[23:26] == b"\x9d\x01\x2a":
        width, height = _number(data, 26, 2, "little"), _number(data, 28, 2, "little")
        if width is None or height is None:
            return None
        return _size(width & 0x3FFF, height & 0x3FFF)
    if chunk == b"VP8L" and data[20:21] == b"\x2f":
        bits = _number(data, 21, 4, "little")
        if bits is None:
            return None
        return _size((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1)
    if chunk == b"VP8X":
        width, height = _number(data, 24, 3, "little"), _number(data, 27, 3, "little")
        if width is None or height is None:
            return None
        return _size(width + 1, height + 1)
    return None


def _jpeg(data: bytes) -> tuple[int, int] | None:
    index = 2
    while index + 4 <= len(data):
        if data[index] != 0xFF:
            return None
        marker = data[index + 1]
        if marker == 0xFF:
            index += 1
            continue
        if marker == 0x01 or 0xD0 <= marker <= 0xD9:
            index += 2
            continue
        length = _number(data, index + 2, 2, "big")
        if length is None or length < 2:
            return None
        if 0xC0 <= marker <= 0xCF and marker not in {0xC4, 0xC8, 0xCC}:
            return _size(
                _number(data, index + 7, 2, "big"), _number(data, index + 5, 2, "big")
            )
        index += 2 + length
    return None
