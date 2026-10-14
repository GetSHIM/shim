import base64
from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import io
import subprocess
import sys
import threading
from typing import Any
from uuid import UUID

from PIL import Image
import pytest

from shim.core import isolation
import shim.gateway.image_rules as image_rules
import shim.gateway.pipeline.transform_band as transform_band
from shim.gateway.contracts.context import (
    AuditPolicy,
    GatewayContext,
    PrivacyPolicy,
    TierPolicy,
)
from shim.gateway.contracts.ids import ApiKeyId, ProviderId, RequestId, TenantId
from shim.gateway.kernel.result import PreparedInference, ProviderTarget
from shim.gateway.media import classify_media
from shim.gateway.pipeline.transform_band import TransformBandStage
from shim.gateway.request_policy import BandSettings, RequestPolicyContext
from shim.observability.metrics import IMAGE_DOWNSCALE_TOTAL


def _gradient(width: int, height: int, mode: str = "RGB") -> Image.Image:
    image = Image.linear_gradient("L").resize((width, height))
    if mode == "L":
        return image
    if mode == "LA":
        return Image.merge("LA", (image, image))
    rgb = Image.merge(
        "RGB",
        (
            image,
            image.transpose(Image.Transpose.ROTATE_90).resize((width, height)),
            image,
        ),
    )
    return rgb.convert(mode)


def _encode(image: Image.Image, image_format: str, **options: Any) -> bytes:
    output = io.BytesIO()
    image.save(output, format=image_format, **options)
    return output.getvalue()


JPEG = _encode(_gradient(4000, 3000), "JPEG", quality=95)
PNG = _encode(_gradient(3000, 2000), "PNG")
WEBP = _encode(_gradient(3000, 2000), "WEBP", quality=80)
SMALL = _encode(_gradient(800, 600), "PNG")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _anthropic_image(
    data: bytes, mime: str = "image/jpeg", **fields: Any
) -> dict[str, Any]:
    return {
        "type": "image",
        "source": {"type": "base64", "media_type": mime, "data": _b64(data)},
        **fields,
    }


def _prepared(
    protocol: str,
    content: list[Any],
    *,
    model: str = "claude-haiku-4-5",
    on: bool = True,
    **fields: Any,
) -> PreparedInference:
    context = GatewayContext(
        request_id=RequestId("req_image"),
        tenant_id=TenantId(UUID("11111111-1111-1111-1111-111111111111")),
        actor_type="api_key",
        api_key_id=ApiKeyId(UUID("22222222-2222-2222-2222-222222222222")),
        user_id=None,
        endpoint="/v1/messages",
        started_at=datetime(2026, 10, 14, tzinfo=UTC),
        tier_policy=TierPolicy(rate_limit_rpm=60),
        privacy_policy=PrivacyPolicy(pii_mode="scrub"),
        audit_policy=AuditPolicy(mode="best_effort"),
    )
    key = "input" if protocol == "responses" else "messages"
    payload = {"model": model, key: [{"role": "user", "content": content}], **fields}
    if protocol == "messages":
        payload["max_tokens"] = 16
    return PreparedInference(
        context=context,
        payload=payload,
        provider=ProviderId("anthropic" if protocol == "messages" else "openai"),
        protocol=protocol,  # type: ignore[arg-type]
        model=model,
        stream=False,
        policy=RequestPolicyContext(rate_limit_key_hash="h", tier="t"),
        pii_config=None,
        band=BandSettings(image_downscale=on),
        media=classify_media(payload),
    )


async def _run(prepared: PreparedInference) -> PreparedInference:
    return await TransformBandStage().run(prepared)


def _image_at(payload: dict[str, Any], *path: Any) -> Image.Image:
    value: Any = payload
    for step in path:
        value = value[step]
    return Image.open(io.BytesIO(base64.b64decode(value.partition(",")[2] or value)))


def _entry(prepared: PreparedInference) -> dict[str, Any] | None:
    found = [
        entry
        for entry in prepared.transforms_applied or ()
        if entry["id"] == "image_downscale"
    ]
    return found[0] if found else None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("data", "mime", "model", "size"),
    [
        (JPEG, "image/jpeg", "claude-haiku-4-5", (1270, 952)),
        (JPEG, "image/jpeg", "claude-opus-5-5", (2212, 1659)),
        (PNG, "image/png", "claude-haiku-4-5", (1344, 896)),
        (WEBP, "image/webp", "claude-haiku-4-5", (1344, 896)),
    ],
    ids=["jpeg-standard", "jpeg-high", "png", "webp"],
)
async def test_an_oversized_image_is_shrunk_to_the_providers_size(
    data, mime, model, size
) -> None:
    prepared = _prepared(
        "messages",
        [{"type": "text", "text": "describe"}, _anthropic_image(data, mime)],
        model=model,
    )

    done = await _run(prepared)

    part = done.payload["messages"][0]["content"][1]
    image = _image_at(done.payload, "messages", 0, "content", 1, "source", "data")
    assert (
        image.size == size
        and image.format
        == {"image/jpeg": "JPEG", "image/png": "PNG", "image/webp": "WEBP"}[mime]
    )
    assert part["source"]["media_type"] == mime
    assert done.payload["messages"][0]["content"][0] == {
        "type": "text",
        "text": "describe",
    }
    entry = _entry(done)
    assert entry is not None
    assert (
        entry["items"] == 1
        and entry["rules"] == 3
        and entry["library"].startswith("pillow-")
    )
    assert entry["images"] == [
        {
            "format": image.format.lower(),
            "before": list(Image.open(io.BytesIO(data)).size),
            "after": list(size),
            "before_bytes": len(data),
            "after_bytes": len(base64.b64decode(part["source"]["data"])),
        }
    ]
    assert entry["after_bytes"] < entry["before_bytes"] and entry["skipped"] == {}
    assert entry["before_chars"] == len(_b64(data)) and entry["after_chars"] == len(
        part["source"]["data"]
    )


def _gif() -> bytes:
    return _encode(_gradient(3000, 2000).convert("P"), "GIF")


def _animated_webp() -> bytes:
    frames = [
        _gradient(3000, 2000),
        _gradient(3000, 2000).transpose(Image.Transpose.FLIP_LEFT_RIGHT),
    ]
    return _encode(frames[0], "WEBP", save_all=True, append_images=frames[1:])


def _rotated() -> bytes:
    exif = Image.Exif()
    exif[0x0112] = 6
    return _encode(_gradient(4000, 3000), "JPEG", exif=exif.tobytes())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (_gif(), "unsupported"),
        (_animated_webp(), "unsupported"),
        (_rotated(), "unsupported"),
        (_encode(_gradient(4000, 3000).convert("CMYK"), "JPEG"), "unsupported"),
        (JPEG[:4000], "corrupt"),
        (SMALL, "below_threshold"),
    ],
    ids=["gif", "animated-webp", "rotated", "cmyk", "truncated", "small"],
)
async def test_an_image_left_alone_says_why(data, reason) -> None:
    before = IMAGE_DOWNSCALE_TOTAL.labels(outcome=reason)._value.get()
    prepared = _prepared("messages", [_anthropic_image(data)])

    done = await _run(prepared)

    assert done.payload == prepared.payload and _entry(done) is None
    assert IMAGE_DOWNSCALE_TOTAL.labels(outcome=reason)._value.get() == before + 1


@pytest.mark.parametrize(
    ("mode", "kept"),
    [
        ("L", "L"),
        ("LA", "LA"),
        ("RGB", "RGB"),
        ("RGBA", "RGBA"),
        ("P", "RGB"),
        ("PA", "RGBA"),
    ],
)
def test_each_kept_mode_is_resized_in_its_own_mode(mode, kept) -> None:
    image = _gradient(300, 200, mode if mode in {"L", "LA", "RGB", "RGBA"} else "RGB")
    if mode in {"P", "PA"}:
        image = image.convert("P")
    if mode == "PA":
        image.info["transparency"] = 0
    data = _encode(image, "PNG")

    resized, image_format = image_rules.resize(data, (150, 100))

    shrunk = Image.open(io.BytesIO(resized))
    assert (shrunk.size, shrunk.mode, image_format) == ((150, 100), kept, "png")


@pytest.mark.asyncio
async def test_clients_that_rely_on_the_original_frame_are_left_alone() -> None:
    oversized = _anthropic_image(JPEG, transformations={"oversized_image": "error"})
    in_result = {
        "type": "tool_result",
        "tool_use_id": "t1",
        "content": [_anthropic_image(JPEG)],
    }
    screenshot = {
        "type": "computer_call_output",
        "call_id": "c",
        "output": {
            "type": "computer_screenshot",
            "image_url": f"data:image/jpeg;base64,{_b64(JPEG)}",
        },
    }

    for prepared in (
        _prepared("messages", [oversized]),
        _prepared("messages", [in_result]),
        replace(
            _prepared("responses", [], model="gpt-5.4"),
            payload={"model": "gpt-5.4", "input": [screenshot]},
            media=classify_media({"input": [screenshot]}),
        ),
    ):
        done = await _run(prepared)
        assert done.payload == prepared.payload and _entry(done) is None


@pytest.mark.asyncio
async def test_unknown_models_and_unlisted_deployments_are_left_alone() -> None:
    unknown = _prepared("messages", [_anthropic_image(JPEG)], model="claude-instant")
    deployment = replace(
        _prepared("messages", [_anthropic_image(JPEG)]),
        target=ProviderTarget(
            deployment_id="d",
            base_url="https://models.internal.test/v1",
            upstream_model="claude-haiku-4-5",
            credential_reference="c",
            timeout_seconds=30,
            declared_version="1",
        ),
    )

    for prepared in (unknown, deployment):
        done = await _run(prepared)
        assert done.payload == prepared.payload


@pytest.mark.asyncio
async def test_too_many_pixels_are_never_decoded(monkeypatch) -> None:
    monkeypatch.setattr(transform_band, "MAX_IMAGE_PIXELS", 12_000_000 - 1)

    def fail(*_args, **_kwargs):
        raise AssertionError("decoded")

    monkeypatch.setattr(isolation, "run", fail)
    prepared = _prepared("messages", [_anthropic_image(JPEG)])

    assert (await _run(prepared)).payload == prepared.payload


@pytest.mark.asyncio
async def test_a_result_that_is_not_smaller_keeps_the_original(monkeypatch) -> None:
    monkeypatch.setitem(image_rules._ENCODE, "PNG", {"compress_level": 0})
    # In this process, so the patched encoder is the one used.
    monkeypatch.setattr(
        isolation, "run", lambda function, *args, deadline: function(*args)
    )
    data = _encode(Image.new("RGB", (3000, 2000), (10, 20, 30)), "PNG", optimize=True)
    prepared = _prepared("messages", [_anthropic_image(data, "image/png")])

    done = await _run(prepared)

    assert done.payload == prepared.payload and _entry(done) is None


@pytest.mark.asyncio
async def test_a_thinking_bound_request_is_left_alone_with_a_verdict() -> None:
    prepared = _prepared(
        "messages", [_anthropic_image(JPEG)], thinking={"type": "adaptive"}
    )

    done = await _run(prepared)

    assert done.payload == prepared.payload
    assert [
        (verdict.rule_id, verdict.stage, verdict.outcome, verdict.reason_code)
        for verdict in done.policy_verdicts
    ] == [
        ("transforms.image_downscale", "transforms", "skip", "TRANSFORM_THINKING_BOUND")
    ]


@pytest.mark.asyncio
async def test_openai_targets_follow_the_effective_detail() -> None:
    def chat(**image_url: Any) -> PreparedInference:
        part = {
            "type": "image_url",
            "image_url": {"url": f"data:image/jpeg;base64,{_b64(JPEG)}", **image_url},
        }
        return _prepared("chat", [part], model="gpt-5.4")

    sizes = []
    for prepared in (chat(), chat(detail="original"), chat(detail="low")):
        done = await _run(prepared)
        url = done.payload["messages"][0]["content"][0]["image_url"]["url"]
        assert url.startswith("data:image/jpeg;base64,")
        sizes.append(
            _image_at(
                done.payload, "messages", 0, "content", 0, "image_url", "url"
            ).size
        )

    assert sizes == [(1824, 1368), (3669, 2752), (2048, 1536)]


@pytest.mark.asyncio
async def test_a_later_turn_gets_the_same_bytes_for_the_same_image() -> None:
    first = await _run(_prepared("messages", [_anthropic_image(JPEG)]))
    turns = [
        {"role": "user", "content": [_anthropic_image(JPEG)]},
        {"role": "assistant", "content": "a gradient"},
        {"role": "user", "content": "and now?"},
    ]
    prepared = _prepared("messages", [])
    later = await _run(
        replace(
            prepared,
            payload={**prepared.payload, "messages": turns},
            media=classify_media({"messages": turns}),
        )
    )

    assert later.payload["messages"][0] == first.payload["messages"][0]


@pytest.mark.asyncio
async def test_the_record_lists_at_most_its_cap_of_images(monkeypatch) -> None:
    monkeypatch.setattr(transform_band, "_RECORDED_IMAGES", 1)
    prepared = _prepared(
        "messages",
        [
            _anthropic_image(JPEG),
            _anthropic_image(PNG, "image/png"),
            _anthropic_image(SMALL, "image/png"),
        ],
    )

    entry = _entry(await _run(prepared))

    assert entry is not None and entry["items"] == 2 and len(entry["images"]) == 1
    assert entry["skipped"] == {"below_threshold": 1}


@pytest.mark.asyncio
async def test_the_resize_runs_in_a_worker_process_off_the_event_loop(
    monkeypatch,
) -> None:
    calls: list[tuple[object, int]] = []
    run = isolation.run

    def recording(function, *args, deadline):
        calls.append((function, threading.get_ident()))
        return run(function, *args, deadline=deadline)

    monkeypatch.setattr(isolation, "run", recording)

    done = await _run(_prepared("messages", [_anthropic_image(JPEG)]))

    assert _entry(done) is not None
    assert calls == [(image_rules.resize, calls[0][1])]
    assert calls[0][1] != threading.get_ident()


@pytest.mark.asyncio
async def test_a_text_request_never_imports_pillow(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "PIL", None)
    prepared = replace(
        _prepared("messages", [{"type": "text", "text": "hi"}]), media=()
    )

    assert (await _run(prepared)).payload == prepared.payload


def test_the_same_image_gives_the_same_bytes_in_another_process() -> None:
    script = (
        "import base64, hashlib, sys\n"
        "from shim.gateway.image_rules import resize\n"
        "raw = base64.b64decode(sys.stdin.read())\n"
        "print(hashlib.sha256(resize(raw, (1270, 952))[0]).hexdigest())\n"
    )
    for data in (JPEG, PNG, WEBP):
        digests = {
            subprocess.run(
                [sys.executable, "-c", script],
                input=_b64(data),
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            for _ in range(2)
        }
        local = hashlib.sha256(image_rules.resize(data, (1270, 952))[0]).hexdigest()
        assert digests == {local}


@pytest.mark.asyncio
async def test_base64_that_does_not_decode_leaves_the_request_alone() -> None:
    image = _anthropic_image(JPEG)
    image["source"]["data"] = image["source"]["data"][:-1]
    prepared = _prepared("messages", [image])

    done = await _run(prepared)

    assert done.payload == prepared.payload and _entry(done) is None


def test_a_jpeg_comment_is_not_carried_over() -> None:
    data = _encode(_gradient(400, 300), "JPEG", comment=b"TCKN 10000000146")
    assert Image.open(io.BytesIO(data)).info["comment"]

    resized, _ = image_rules.resize(data, (200, 150))

    assert "comment" not in Image.open(io.BytesIO(resized)).info
    assert b"10000000146" not in resized


def test_pillow_refuses_more_pixels_than_the_cap() -> None:
    data = _encode(Image.new("L", (9000, 8000)), "PNG")

    with pytest.raises(Image.DecompressionBombWarning):
        image_rules.resize(data, (100, 89))


@pytest.mark.asyncio
async def test_a_request_without_images_gets_no_thinking_bound_verdict() -> None:
    before = IMAGE_DOWNSCALE_TOTAL.labels(outcome="thinking_bound")._value.get()
    prepared = replace(
        _prepared(
            "messages",
            [{"type": "text", "text": "hi"}],
            thinking={"type": "adaptive"},
        ),
        media=(),
    )

    done = await _run(prepared)

    assert done.policy_verdicts == []
    assert IMAGE_DOWNSCALE_TOTAL.labels(outcome="thinking_bound")._value.get() == before
