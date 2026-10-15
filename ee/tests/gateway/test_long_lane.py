"""The lane's size measure is admission's TPM unit, byte for byte."""

from __future__ import annotations

import pytest

from shim.gateway.pipeline.admission import _estimate_input_tokens
from shim_enterprise.tenants.deployments import approximate_input_tokens

TURKISH = "Şirketin 2026 bütçesini özetle: ğüşıöç İĞÜŞÖÇ " * 40


@pytest.mark.parametrize(
    "payload",
    [
        {"model": "m", "messages": [{"role": "user", "content": TURKISH}]},
        {"model": "m", "input": [{"role": "user", "content": TURKISH}]},
        {
            "model": "m",
            "max_tokens": 64,
            "system": "Kısa yaz.",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": TURKISH}]}
            ],
        },
        {"model": "m", "messages": [{"role": "user", "content": "x"}]},
    ],
    ids=["chat", "responses", "messages", "short"],
)
def test_the_measure_is_admissions_approximate_tokens(payload) -> None:
    input_bytes, _ = _estimate_input_tokens(payload, "identity")

    assert approximate_input_tokens(payload) == -(-input_bytes // 4)


def test_a_lone_surrogate_is_measured_and_left_to_admission() -> None:
    payload = {"model": "m", "messages": [{"role": "user", "content": "a\ud800b"}]}

    assert approximate_input_tokens(payload) >= 1
