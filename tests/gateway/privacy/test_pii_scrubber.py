from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import time
from types import SimpleNamespace
from unittest.mock import Mock

from fastapi import HTTPException
import pytest

import shim.gateway.pipeline.privacy as privacy_module
from shim.gateway.pipeline.privacy import scan_response, scrub_payload
from shim.privacy.deanonymizer import (
    AnthropicStreamRestorer,
    OpenAIStreamRestorer,
    restore_anthropic_payload,
    restore_openai_payload,
)
from shim.privacy import pii_scrubber as pii_scrubber_module
from shim.privacy.pii_scrubber import (
    PIIInputTooLarge,
    PIIScrubberService,
    placeholder_period_key,
)
from shim.privacy.policies import (
    PrivacyAction,
    PrivacyOutcome,
    effective_entity_actions,
)


DEFAULT_ACTIONS = effective_entity_actions()


@pytest.fixture
def scrubber() -> PIIScrubberService:
    return PIIScrubberService()


@pytest.mark.parametrize(
    ("text", "entity_type"),
    [
        ("Email alice@example.com", "EMAIL_ADDRESS"),
        ("Card 4111 1111 1111 1111", "CREDIT_CARD"),
        ('{"password": "SuperSecret123!"}', "SECRET"),
        ("Phone +90 532 123 45 67", "PHONE_NUMBER"),
        ("TCKN 10000000146", "TR_NATIONAL_ID"),
    ],
)
def test_sensitive_values_use_random_typed_placeholders(
    scrubber: PIIScrubberService,
    text: str,
    entity_type: str,
) -> None:
    first, first_map = scrubber.scrub(text, DEFAULT_ACTIONS)
    second, second_map = scrubber.scrub(text, DEFAULT_ACTIONS)

    assert first != second
    assert first_map != second_map
    assert any(key.startswith(f"<{entity_type}_") for key in first_map)
    assert all(value not in first for value in first_map.values())
    assert scrubber.deanonymize(first, first_map) == text
    assert scrubber.deanonymize(second, second_map) == text


def test_placeholder_does_not_expose_an_unkeyed_value_digest(
    scrubber: PIIScrubberService,
) -> None:
    email = "alice@example.com"
    _, mapping = scrubber.scrub(email, DEFAULT_ACTIONS)

    assert hashlib.sha256(email.encode()).hexdigest()[:32] not in next(iter(mapping))


def test_known_placeholder_is_reused_only_when_explicitly_scoped(
    scrubber: PIIScrubberService,
) -> None:
    email = "alice@example.com"
    first, mapping = scrubber.scrub(email, DEFAULT_ACTIONS)

    continued, continued_map = scrubber.scrub(
        email, DEFAULT_ACTIONS, known_placeholders=mapping
    )
    unrelated, _ = scrubber.scrub(email, DEFAULT_ACTIONS)

    assert continued == first
    assert continued_map == mapping
    assert unrelated != first


def test_disabled_scrubbing_preserves_the_original_text(
    scrubber: PIIScrubberService,
) -> None:
    config = effective_entity_actions(
        {
            "block_email": False,
            "block_phone": False,
            "block_credit_card": False,
            "block_secrets": False,
            "block_pii_tr": False,
        }
    )

    assert scrubber.scrub("literal%20value", config) == ("literal%20value", {})


def test_analyzer_limit_is_reported_as_request_too_large(
    scrubber: PIIScrubberService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pii_scrubber_module, "MAX_ANALYZABLE_TEXT_LENGTH", 3)

    with pytest.raises(PIIInputTooLarge):
        scrubber.scrub("safe", DEFAULT_ACTIONS)
    with pytest.raises(HTTPException) as error:
        scrub_payload({"input": "safe"}, DEFAULT_ACTIONS, scrubber)

    assert error.value.status_code == 413
    assert error.value.detail["code"] == "REQUEST_TOO_LARGE"


def test_clean_text_preserves_the_original_representation(
    scrubber: PIIScrubberService,
) -> None:
    text = "Ｆｕｌｌ%20ｗｉｄｔｈ\u200b"

    assert scrubber.scrub(text, DEFAULT_ACTIONS) == (text, {})


@pytest.mark.parametrize(
    ("text", "entity_type", "source_value"),
    [
        ("Contact: alice%40example.com", "EMAIL_ADDRESS", "alice%40example.com"),
        (
            "Contact: alice%E2%80%8B%40example.com",
            "EMAIL_ADDRESS",
            "alice%E2%80%8B%40example.com",
        ),
        (
            "Contact: alice\u200b@example.com",
            "EMAIL_ADDRESS",
            "alice\u200b@example.com",
        ),
        ('{"password": "abcﬃdef"}', "SECRET", "abcﬃdef"),
    ],
)
def test_transformed_pii_uses_original_source_spans(
    scrubber: PIIScrubberService,
    text: str,
    entity_type: str,
    source_value: str,
) -> None:
    detection = next(
        item
        for item in scrubber.analyze(text, DEFAULT_ACTIONS)
        if item["type"] == entity_type
    )
    scrubbed, mapping = scrubber.scrub(text, DEFAULT_ACTIONS)

    assert text[detection["start"] : detection["end"]] == source_value
    assert set(mapping.values()) == {source_value}
    assert scrubber.deanonymize(scrubbed, mapping) == text


def test_distinct_values_cannot_share_a_placeholder(
    scrubber: PIIScrubberService,
) -> None:
    first = "user92207@example.com"
    second = "user134538@example.com"

    scrubbed, mapping = scrubber.scrub(f"{first} {second}", DEFAULT_ACTIONS)

    assert len(mapping) == 2
    assert set(mapping.values()) == {first, second}
    assert scrubber.deanonymize(scrubbed, mapping) == f"{first} {second}"


def test_representative_plaintext_branches_are_scrubbed() -> None:
    email = "alice@example.com"
    payload = {
        "messages": [
            {
                "role": "user",
                "content": "safe",
                "refusal": email,
            }
        ],
        "tools": [
            {
                "type": "custom",
                "name": "lookup",
                "environment": {"CONTACT": email},
                "format": {"schema": {"default": email}},
            }
        ],
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "executableCode": {
                            "language": "PYTHON",
                            "code": f"# owner: {email}",
                        }
                    }
                ],
            }
        ],
    }

    safe, mapping = scrub_payload(payload, DEFAULT_ACTIONS, PIIScrubberService())

    assert email not in json.dumps(safe)
    assert set(mapping.values()) == {email}


def test_current_openai_and_anthropic_tool_blocks_scrub_only_content() -> None:
    email = "alice@example.com"
    payload = {
        "input": [
            {
                "type": "program",
                "id": "prog_1",
                "call_id": "call_1",
                "code": f"notify({email!r})",
                "fingerprint": "fp_1",
            },
            {
                "type": "program_output",
                "id": "out_1",
                "call_id": "call_1",
                "result": {"contact": email, "customer_id": email},
            },
            {
                "type": "tool_search_call",
                "id": "search_1",
                "call_id": "call_2",
                "arguments": {"query": email},
            },
            {
                "type": "mcp_call",
                "id": "mcp_1",
                "server_label": "crm",
                "name": "lookup",
                "arguments": {"contact": email},
                "output": email,
            },
        ],
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "mcp_tool_use",
                        "id": "toolu_1",
                        "name": "lookup",
                        "server_name": "crm",
                        "input": {"contact": email},
                    },
                    {
                        "type": "mcp_tool_result",
                        "tool_use_id": "toolu_1",
                        "content": email,
                    },
                    {
                        "type": "compaction",
                        "content": email,
                        "encrypted_content": "opaque_compaction",
                    },
                    {"type": "redacted_thinking", "data": "opaque_thinking"},
                ],
            }
        ],
        "tools": [
            {
                "type": "code_interpreter",
                "container": {"type": "auto", "file_ids": ["file_1"]},
            },
            {
                "type": "mcp",
                "server_label": "crm",
                "authorization": "opaque_token",
                "headers": {"X-Token": "opaque_token"},
                "server_description": f"Find {email}",
            },
        ],
    }

    safe, mapping = scrub_payload(payload, DEFAULT_ACTIONS, PIIScrubberService())

    assert email not in json.dumps(safe)
    assert set(mapping.values()) == {email}
    assert safe["input"][0]["id"] == "prog_1"
    assert safe["input"][0]["fingerprint"] == "fp_1"
    assert safe["tools"][0]["container"]["file_ids"] == ["file_1"]
    assert safe["messages"][0]["content"][2]["encrypted_content"] == (
        "opaque_compaction"
    )
    assert safe["messages"][0]["content"][3]["data"] == "opaque_thinking"


@pytest.mark.parametrize(
    "payload",
    [
        {
            "input": [
                {
                    "type": "computer_call_output",
                    "call_id": "call_1",
                    "output": {
                        "type": "computer_screenshot",
                        "image_url": "data:image/png;base64,b3BhcXVl",
                    },
                }
            ]
        },
        {
            "tools": [
                {
                    "type": "image_generation",
                    "input_image_mask": {"file_id": "file_1"},
                }
            ]
        },
        {
            "input": [
                {
                    "type": "image_generation_call",
                    "id": "image_1",
                    "result": "b3BhcXVl",
                    "status": "completed",
                }
            ]
        },
    ],
)
def test_current_opaque_media_blocks_are_rejected(payload: dict[str, object]) -> None:
    with pytest.raises(HTTPException, match="opaque media"):
        scrub_payload(payload, DEFAULT_ACTIONS, PIIScrubberService())


def test_payload_reuses_one_placeholder_for_repeated_values() -> None:
    email = "alice@example.com"

    safe, mapping = scrub_payload(
        {"input": email, "instructions": f"Contact {email}"},
        DEFAULT_ACTIONS,
        PIIScrubberService(),
    )

    placeholder = next(iter(mapping))
    assert safe == {
        "input": placeholder,
        "instructions": f"Contact {placeholder}",
    }


def _media_payload(protocol: str, part: dict[str, object]) -> dict[str, object]:
    if protocol == "google":
        return {"contents": [{"role": "user", "parts": [part]}]}
    return {"messages": [{"role": "user", "content": [part]}]}


@pytest.mark.parametrize(
    ("protocol", "part"),
    [
        (
            "openai",
            {
                "type": "image_url",
                "image_url": "https://example.test/image.png",
            },
        ),
        (
            "openai",
            {"type": "input_audio", "input_audio": {"data": "c2Vuc2l0aXZl"}},
        ),
        ("openai", {"type": "file", "file": {"file_data": "c2Vuc2l0aXZl"}}),
        ("openai", {"type": "input_file", "file_id": "file_123"}),
        (
            "anthropic",
            {
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": "c2Vuc2l0aXZl",
                },
            },
        ),
        (
            "anthropic",
            {
                "type": "document",
                "source": {
                    "type": "base64",
                    "media_type": "application/pdf",
                    "data": "c2Vuc2l0aXZl",
                },
            },
        ),
        (
            "anthropic",
            {
                "type": "document",
                "source": {"type": "file", "file_id": "file_123"},
            },
        ),
        (
            "anthropic",
            {
                "type": "image",
                "source": {"type": "file", "file_id": "file_123"},
            },
        ),
        (
            "google",
            {
                "inlineData": {
                    "mimeType": "image/png",
                    "data": "c2Vuc2l0aXZl",
                }
            },
        ),
    ],
)
def test_scrubbing_rejects_uninspectable_media(
    protocol: str,
    part: dict[str, object],
) -> None:
    payload = _media_payload(protocol, part)
    with pytest.raises(HTTPException, match="opaque media") as error:
        scrub_payload(payload, DEFAULT_ACTIONS, PIIScrubberService())
    assert error.value.status_code == 400
    assert error.value.detail["code"] == "PRIVACY_POLICY_BLOCKED"


def test_disabled_scrubbing_allows_uninspectable_media() -> None:
    payload = _media_payload(
        "openai",
        {"type": "image_url", "image_url": "https://example.test/image.png"},
    )
    disabled = effective_entity_actions(
        {
            "block_email": False,
            "block_phone": False,
            "block_credit_card": False,
            "block_secrets": False,
            "block_pii_tr": False,
        }
    )
    known_placeholders = {"<EMAIL_ADDRESS_deadbeef>": "alice@example.com"}
    scrubber = Mock(spec=PIIScrubberService)

    safe, mapping = scrub_payload(
        payload,
        disabled,
        scrubber,
        known_placeholders=known_placeholders,
    )

    assert safe == payload
    assert safe is not payload
    assert mapping == known_placeholders
    assert mapping is not known_placeholders
    scrubber.scrub.assert_not_called()


def test_media_detection_ignores_tool_schemas_and_unhashable_types() -> None:
    payload = {
        "input": [
            {"type": {"kind": "record"}, "text": "safe"},
            {
                "type": "function_call_output",
                "call_id": "call_1",
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
    }

    assert scrub_payload(payload, DEFAULT_ACTIONS, PIIScrubberService()) == (
        payload,
        {},
    )


@pytest.mark.parametrize(
    "payload",
    [
        {
            "input": [
                {
                    "type": "function_call_output",
                    "call_id": "call_1",
                    "output": [{"type": "file", "file": {"file_data": "opaque"}}],
                }
            ]
        },
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "lookup",
                            "input": {
                                "type": "image",
                                "source": {"type": "base64", "data": "opaque"},
                            },
                        }
                    ],
                }
            ]
        },
    ],
)
def test_scrubbing_rejects_opaque_media_nested_in_tool_data(
    payload: dict[str, object],
) -> None:
    with pytest.raises(HTTPException, match="opaque media"):
        scrub_payload(payload, DEFAULT_ACTIONS, PIIScrubberService())


def test_pii_in_protocol_identifier_is_rejected_without_rewriting_valid_ids() -> None:
    safe, mapping = scrub_payload(
        {
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_1",
                            "name": "lookup",
                            "input": {
                                "id": "alice@example.com",
                                "descriptor": {
                                    "type": "record",
                                    "owner": "alice@example.com",
                                },
                            },
                        }
                    ],
                }
            ]
        },
        DEFAULT_ACTIONS,
        PIIScrubberService(),
    )

    tool = safe["messages"][0]["content"][0]
    assert tool["id"] == "toolu_1"
    assert tool["name"] == "lookup"
    assert tool["input"]["id"] != "alice@example.com"
    assert tool["input"]["descriptor"]["type"] == "record"
    assert tool["input"]["descriptor"]["owner"] != "alice@example.com"
    assert mapping

    with pytest.raises(HTTPException, match="protocol identifier") as error:
        scrub_payload(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "alice@example.com",
                                "name": "lookup",
                                "input": {},
                            }
                        ],
                    }
                ]
            },
            DEFAULT_ACTIONS,
            PIIScrubberService(),
        )
    assert error.value.status_code == 400
    assert error.value.detail["code"] == "PRIVACY_POLICY_BLOCKED"


def test_validated_request_model_bypasses_identifier_pii_detection() -> None:
    model = "claude-sonnet-4-5-20250929"
    safe, mapping = scrub_payload(
        {
            "model": model,
            "messages": [{"role": "user", "content": "Email alice@example.com"}],
        },
        DEFAULT_ACTIONS,
        PIIScrubberService(),
        request_model=model,
    )

    assert safe["model"] == model
    assert "alice@example.com" not in json.dumps(safe["messages"])
    assert mapping


def test_model_pii_still_rejected_when_not_the_validated_request_model() -> None:
    with pytest.raises(HTTPException, match="protocol identifier") as error:
        scrub_payload(
            {"model": "private@example.com"},
            DEFAULT_ACTIONS,
            PIIScrubberService(),
            request_model="claude-sonnet-4-5",
        )
    assert error.value.detail["code"] == "PRIVACY_POLICY_BLOCKED"


def test_opaque_protocol_values_are_preserved_when_clean_and_rejected_with_pii() -> (
    None
):
    safe, mapping = scrub_payload(
        {
            "input": [
                {
                    "type": "reasoning",
                    "encrypted_content": "gAAAAABopaque",
                    "signature": "sig_123",
                }
            ]
        },
        DEFAULT_ACTIONS,
        PIIScrubberService(),
    )

    assert safe["input"][0]["encrypted_content"] == "gAAAAABopaque"
    assert safe["input"][0]["signature"] == "sig_123"
    assert mapping == {}

    with pytest.raises(HTTPException, match="protocol identifier"):
        scrub_payload(
            {
                "input": [
                    {
                        "type": "reasoning",
                        "encrypted_content": "alice@example.com",
                    }
                ]
            },
            DEFAULT_ACTIONS,
            PIIScrubberService(),
        )


def test_legacy_placeholders_remain_restorable(
    scrubber: PIIScrubberService,
) -> None:
    placeholder = "<EMAIL_ADDRESS_deadbeef>"

    assert (
        scrubber.deanonymize(
            placeholder,
            {placeholder: "alice@example.com"},
        )
        == "alice@example.com"
    )


def test_private_key_is_scrubbed_as_one_secret(
    scrubber: PIIScrubberService,
) -> None:
    private_key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "c2VjcmV0LWtleS1tYXRlcmlhbA==\n"
        "-----END PRIVATE KEY-----"
    )

    scrubbed, mapping = scrubber.scrub(private_key, DEFAULT_ACTIONS)

    assert len(mapping) == 1
    assert next(iter(mapping)).startswith("<SECRET_")
    assert list(mapping.values()) == [private_key]
    assert private_key not in scrubbed


def test_a_spaced_iban_is_masked_whole_even_where_a_card_fits_inside(
    scrubber: PIIScrubberService,
) -> None:
    iban = "TR96 1569 9085 0078 9107 8735 82"

    scrubbed, mapping = scrubber.scrub(f"Ödeme {iban} hesabına", DEFAULT_ACTIONS)

    assert list(mapping.values()) == [iban]
    assert next(iter(mapping)).startswith("<IBAN_CODE_")
    assert "TR96" not in scrubbed
    assert "8735 82" not in scrubbed


@pytest.mark.parametrize("card", ["9792 0000 0000 0003", "2221-0000-0000-0009"])
def test_troy_and_mastercard_two_series_are_one_card(
    scrubber: PIIScrubberService,
    card: str,
) -> None:
    scrubbed, mapping = scrubber.scrub(f"Kart {card} ile öde", DEFAULT_ACTIONS)

    assert list(mapping.values()) == [card]
    assert next(iter(mapping)).startswith("<CREDIT_CARD_")
    assert card not in scrubbed


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("GOOGLE_API_KEY=AIza" + "0" * 35, "AIza" + "0" * 35),
        ("Maps AIza" + "0" * 35, "AIza" + "0" * 35),
        (
            "Slack xoxb-" + "0" * 10 + "-" + "0" * 13,
            "xoxb-" + "0" * 10 + "-" + "0" * 13,
        ),
        ("user xoxp-" + "0" * 24, "xoxp-" + "0" * 24),
        ("Hub hf_" + "0" * 34, "hf_" + "0" * 34),
        ("GitLab glpat-" + "0" * 20, "glpat-" + "0" * 20),
        ("ŞİFRE: x123456", "x123456"),
        ('parolam="Gizli Parola 2026"', "Gizli Parola 2026"),
        ("Geçici şifreniz: Abc12345", "Abc12345"),
        ("sifresi: Abc12345", "Abc12345"),
        ("parolanız: Abc12345", "Abc12345"),
    ],
)
def test_vendor_tokens_and_turkish_passwords_are_one_secret(
    scrubber: PIIScrubberService,
    text: str,
    secret: str,
) -> None:
    scrubbed, mapping = scrubber.scrub(text, DEFAULT_ACTIONS)

    assert len(mapping) == 1
    assert next(iter(mapping)).startswith("<SECRET_")
    assert list(mapping.values()) == [secret]
    assert secret not in scrubbed


@pytest.mark.parametrize(
    ("value", "entity"),
    [
        ("100 000 001 46", "TR_NATIONAL_ID"),
        ("100-000-00-146", "TR_NATIONAL_ID"),
        ("tr33 0006 1005 1978 6457 8413 26", "IBAN_CODE"),
        ("TR33 0006 1005 1978\n  6457 8413 26", "IBAN_CODE"),
        ("jane[at]example.com", "EMAIL_ADDRESS"),
        ("jane( AT )example.com", "EMAIL_ADDRESS"),
    ],
)
def test_identifiers_written_around_the_detector_are_one_placeholder(
    scrubber: PIIScrubberService,
    value: str,
    entity: str,
) -> None:
    text = f"Müşteri bilgisi: {value}, teşekkürler"

    scrubbed, mapping = scrubber.scrub(text, DEFAULT_ACTIONS)

    assert list(mapping.values()) == [value]
    assert next(iter(mapping)).startswith(f"<{entity}_")
    assert value not in scrubbed
    assert scrubber.deanonymize(scrubbed, mapping) == text


@pytest.mark.parametrize(
    ("text", "iban"),
    [
        ("BE68 5390 0754 7034 adlı hesap", "BE68 5390 0754 7034"),
        ("AT61 1904 3002 3457 3201 adet", "AT61 1904 3002 3457 3201"),
        ("BE68 5390 0754 7034\n2026 yılında", "BE68 5390 0754 7034"),
    ],
)
def test_a_lowercase_word_or_next_line_after_an_iban_does_not_hide_it(
    scrubber: PIIScrubberService,
    text: str,
    iban: str,
) -> None:
    assert [
        (finding["type"], text[finding["start"] : finding["end"]])
        for finding in scrubber.analyze(text, DEFAULT_ACTIONS)
    ] == [("IBAN_CODE", iban)]


def test_a_plate_is_one_placeholder_under_the_turkish_identifier_switch(
    scrubber: PIIScrubberService,
) -> None:
    text = "Araç 34 ABC 123, 16 GB 512 RAM"

    scrubbed, mapping = scrubber.scrub(text, DEFAULT_ACTIONS)

    assert list(mapping.values()) == ["34 ABC 123"]
    assert next(iter(mapping)).startswith("<TR_LICENSE_PLATE_")
    assert "16 GB 512" in scrubbed
    assert scrubber.deanonymize(scrubbed, mapping) == text
    assert scrubber.scrub(text, effective_entity_actions({"block_pii_tr": False})) == (
        text,
        {},
    )


def test_native_payload_restores_content_not_metadata_or_ids(
    scrubber: PIIScrubberService,
) -> None:
    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)
    payload = {
        "id": f"item_{placeholder}",
        "metadata": {"text": placeholder},
        "output": [
            {"type": "output_text", "text": f"hello {placeholder}"},
            {
                "type": "function_call",
                "arguments": json.dumps({"email": placeholder}),
            },
            {"type": "custom_tool_call", "input": f"lookup {placeholder}"},
            {"type": "function_call_output", "output": placeholder},
        ],
    }

    restored = restore_openai_payload(payload, mapping, scrubber)

    assert restored["id"] == f"item_{placeholder}"
    assert restored["metadata"]["text"] == placeholder
    assert restored["output"][0]["text"] == "hello alice@example.com"
    assert "alice@example.com" in restored["output"][1]["arguments"]
    assert restored["output"][2]["input"] == "lookup alice@example.com"
    assert restored["output"][3]["output"] == "alice@example.com"


def test_current_tool_outputs_restore_json_but_not_protocol_or_media() -> None:
    scrubber = PIIScrubberService()
    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)
    payload = {
        "output": [
            {
                "type": "program",
                "id": placeholder,
                "call_id": placeholder,
                "code": f"notify({placeholder!r})",
                "fingerprint": placeholder,
            },
            {
                "type": "program_output",
                "id": placeholder,
                "call_id": placeholder,
                "result": {"contact": placeholder, "customer_id": placeholder},
            },
            {
                "type": "mcp_call",
                "id": placeholder,
                "server_label": placeholder,
                "name": placeholder,
                "arguments": {"contact": placeholder, "customer_id": placeholder},
                "output": {"contact": placeholder, "customer_id": placeholder},
            },
            {
                "type": "code_interpreter_call",
                "id": placeholder,
                "container_id": placeholder,
                "code": f"print({placeholder!r})",
                "outputs": [
                    {"type": "logs", "logs": placeholder},
                    {"type": "image", "url": placeholder},
                ],
            },
            {
                "type": "image_generation_call",
                "id": placeholder,
                "result": placeholder,
                "status": "completed",
            },
        ]
    }

    restored = restore_openai_payload(payload, mapping, scrubber)

    program, program_output, mcp, code_interpreter, image_generation = restored[
        "output"
    ]
    assert program["code"] == "notify('alice@example.com')"
    assert program["id"] == program["call_id"] == program["fingerprint"] == placeholder
    assert program_output["result"] == {
        "contact": "alice@example.com",
        "customer_id": "alice@example.com",
    }
    assert (
        mcp["arguments"]
        == mcp["output"]
        == {
            "contact": "alice@example.com",
            "customer_id": "alice@example.com",
        }
    )
    assert mcp["id"] == mcp["server_label"] == mcp["name"] == placeholder
    assert code_interpreter["code"] == "print('alice@example.com')"
    assert code_interpreter["id"] == code_interpreter["container_id"] == placeholder
    assert code_interpreter["outputs"][0]["logs"] == "alice@example.com"
    assert code_interpreter["outputs"][1]["url"] == placeholder
    assert image_generation["result"] == placeholder


def test_anthropic_beta_compaction_restores_content_not_opaque_metadata() -> None:
    scrubber = PIIScrubberService()
    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)
    payload = {
        "content": [
            {
                "type": "compaction",
                "content": f"summary {placeholder}",
                "encrypted_content": placeholder,
            },
            {"type": "redacted_thinking", "data": placeholder},
            {"type": "container_upload", "file_id": placeholder},
        ]
    }

    restored = restore_anthropic_payload(payload, mapping, scrubber)

    assert restored["content"][0] == {
        "type": "compaction",
        "content": "summary alice@example.com",
        "encrypted_content": placeholder,
    }
    assert restored["content"][1]["data"] == placeholder
    assert restored["content"][2]["file_id"] == placeholder


@pytest.mark.parametrize("restore", [restore_openai_payload, restore_anthropic_payload])
def test_future_response_fields_restore_without_changing_protocol_ids(restore) -> None:
    scrubber = PIIScrubberService()
    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)

    restored = restore(
        {
            "id": placeholder,
            "future": {
                "nested": placeholder,
                "future_id": placeholder,
            },
        },
        mapping,
        scrubber,
    )

    assert restored == {
        "id": placeholder,
        "future": {
            "nested": "alice@example.com",
            "future_id": placeholder,
        },
    }


@pytest.mark.parametrize("restore", [restore_openai_payload, restore_anthropic_payload])
def test_provider_protocol_fields_are_never_deanonymized(restore) -> None:
    scrubber = PIIScrubberService()
    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)
    fields = {
        "authorization",
        "cachedContent",
        "cached_content",
        "call_id",
        "container",
        "conversation",
        "headers",
        "inference_geo",
        "language",
        "media_type",
        "model",
        "mimeType",
        "previous_response_id",
        "service_tier",
        "thoughtSignature",
        "thought_signature",
        "tool_call_id",
        "tool_name",
        "tool_names",
        "tool_use_id",
        "uri",
    }
    payload = {field: placeholder for field in fields}

    assert restore(payload, mapping, scrubber) == payload


def test_responses_stream_restores_three_way_splits_and_interleaved_items(
    scrubber: PIIScrubberService,
) -> None:
    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)
    pieces = [placeholder[:7], placeholder[7:15], placeholder[15:]]
    restorer = OpenAIStreamRestorer(mapping, scrubber)
    events = [
        {
            "type": "response.output_text.delta",
            "item_id": "one",
            "output_index": 0,
            "content_index": 0,
            "sequence_number": 1,
            "delta": f"first:{pieces[0]}",
        },
        {
            "type": "response.function_call_arguments.delta",
            "item_id": "two",
            "output_index": 1,
            "content_index": 0,
            "sequence_number": 2,
            "delta": f'{{"email":"{pieces[0]}',
        },
        {
            "type": "response.output_text.delta",
            "item_id": "one",
            "output_index": 0,
            "content_index": 0,
            "sequence_number": 3,
            "delta": pieces[1],
        },
        {
            "type": "response.function_call_arguments.delta",
            "item_id": "two",
            "output_index": 1,
            "content_index": 0,
            "sequence_number": 4,
            "delta": pieces[1],
        },
        {
            "type": "response.output_text.delta",
            "item_id": "one",
            "output_index": 0,
            "content_index": 0,
            "sequence_number": 5,
            "delta": pieces[2],
        },
        {
            "type": "response.function_call_arguments.delta",
            "item_id": "two",
            "output_index": 1,
            "content_index": 0,
            "sequence_number": 6,
            "delta": f'{pieces[2]}"}}',
        },
    ]

    restored = [restorer.restore_response_event(event) for event in events]
    by_item = {
        item_id: "".join(
            event["delta"] for event in restored if event["item_id"] == item_id
        )
        for item_id in ("one", "two")
    }

    assert by_item == {
        "one": "first:alice@example.com",
        "two": '{"email":"alice@example.com"}',
    }
    assert [event["sequence_number"] for event in restored] == list(range(1, 7))


def test_current_text_deltas_restore_without_interpreting_audio_media(
    scrubber: PIIScrubberService,
) -> None:
    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)
    midpoint = len(placeholder) // 2
    restorer = OpenAIStreamRestorer(mapping, scrubber)

    code = [
        restorer.restore_response_event(
            {
                "type": "response.code_interpreter_call_code.delta",
                "item_id": "code_1",
                "output_index": 0,
                "delta": piece,
            }
        )["delta"]
        for piece in (placeholder[:midpoint], placeholder[midpoint:])
    ]
    transcript = [
        restorer.restore_response_event(
            {
                "type": "response.audio.transcript.delta",
                "sequence_number": index,
                "delta": piece,
            }
        )["delta"]
        for index, piece in enumerate(
            (placeholder[:midpoint], placeholder[midpoint:]), start=1
        )
    ]
    audio = restorer.restore_response_event(
        {
            "type": "response.audio.delta",
            "sequence_number": 3,
            "delta": placeholder,
        }
    )

    assert "".join(code) == "alice@example.com"
    assert "".join(transcript) == "alice@example.com"
    assert audio["delta"] == placeholder


def test_anthropic_beta_compaction_stream_restores_split_content(
    scrubber: PIIScrubberService,
) -> None:
    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)
    midpoint = len(placeholder) // 2
    restorer = AnthropicStreamRestorer(mapping, scrubber)

    events = [
        restorer.restore_events(
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "compaction_delta",
                    "content": piece,
                    "encrypted_content": placeholder,
                },
            }
        )[0]
        for piece in (placeholder[:midpoint], placeholder[midpoint:])
    ]

    assert "".join(event["delta"]["content"] for event in events) == (
        "alice@example.com"
    )
    assert all(event["delta"]["encrypted_content"] == placeholder for event in events)


def test_chat_stream_restores_split_tool_arguments(
    scrubber: PIIScrubberService,
) -> None:
    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)
    midpoint = len(placeholder) // 2
    restorer = OpenAIStreamRestorer(mapping, scrubber)

    first = restorer.restore_chat_chunk(
        {
            "id": "chatcmpl_1",
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "function": {"arguments": placeholder[:midpoint]},
                            }
                        ]
                    },
                }
            ],
        }
    )
    second = restorer.restore_chat_chunk(
        {
            "id": "chatcmpl_1",
            "choices": [
                {
                    "index": 0,
                    "delta": {
                        "tool_calls": [
                            {
                                "index": 0,
                                "function": {"arguments": placeholder[midpoint:]},
                            }
                        ]
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }
    )

    arguments = "".join(
        chunk["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
        for chunk in (first, second)
    )
    assert arguments == "alice@example.com"


def test_fragment_carry_is_bounded_and_preserves_every_placeholder_split(scrubber):
    from shim.privacy.deanonymizer import restore_fragment

    placeholder, mapping = scrubber.scrub("alice@example.com", DEFAULT_ACTIONS)
    for token in (placeholder, "<  " + placeholder[1:-1] + "  >"):
        for split in range(len(token) + 1):
            buffers = {}
            output = restore_fragment(buffers, (0,), token[:split], mapping, scrubber)
            output += restore_fragment(buffers, (0,), token[split:], mapping, scrubber)
            assert output == "alice@example.com"
            assert not buffers
    buffers = {}
    assert restore_fragment(buffers, (0,), "<", mapping, scrubber) == ""
    with pytest.raises(ValueError, match="256"):
        for _ in range(256):
            restore_fragment(buffers, (0,), " ", mapping, scrubber)
            assert len(buffers.get((0,), "")) <= 256
    for literal in ("1 < 2", "<UNKNOWN>", "<EM AIL", "plain text"):
        assert restore_fragment({}, (0,), literal, mapping, scrubber) == literal


@pytest.mark.parametrize(
    "text",
    [
        "Sipariş numarası 4829104455",
        "model claude-sonnet-4-5-20250929 kullan",
        "stok SKU-ABC-4829104455 tükendi",
        "artifact build_7.20250929 hazır",
        '{"created": 1757496600, "amount": 2000}',
        "Elapsed: 0.0376118499 s",
        '{"total_cost_usd": 0.03761184999}',
        "Invoice 4829104455 is paid",
        '{"duration_ms": 4155552671}',
        "version 1.2.3.4",
        "release v1.2.3.4",
    ],
)
def test_ids_numbers_and_versions_are_not_phones_or_addresses(
    scrubber: PIIScrubberService,
    text: str,
) -> None:
    assert scrubber.analyze(text, DEFAULT_ACTIONS) == []


@pytest.mark.parametrize(
    ("text", "entity", "value"),
    [
        ('"phone": "4155552671"', "PHONE_NUMBER", "4155552671"),
        ("Telefon 5321234567", "PHONE_NUMBER", "5321234567"),
        ("Bana 05321234567 yaz", "PHONE_NUMBER", "05321234567"),
        ("Tel: 0212 555 12 34", "PHONE_NUMBER", "0212 555 12 34"),
        ("Call (555) 123-4567", "PHONE_NUMBER", "(555) 123-4567"),
        ("Ruf +49 172 5955200", "PHONE_NUMBER", "+49 172 5955200"),
        ("Tel.05321234567", "PHONE_NUMBER", "05321234567"),
        ("Tel.0532 123 45 67", "PHONE_NUMBER", "0532 123 45 67"),
        ("fax.02125551234", "PHONE_NUMBER", "02125551234"),
        ("GSM-05321234567", "PHONE_NUMBER", "05321234567"),
        ("https://wa.me/905321234567", "PHONE_NUMBER", "905321234567"),
        ('{"phone_number": "4155552671"}', "PHONE_NUMBER", "4155552671"),
        ('{"phoneNumber": "4155552671"}', "PHONE_NUMBER", "4155552671"),
        ("Phone number: 4155552671", "PHONE_NUMBER", "4155552671"),
        ("Telefon numarası: 2125551234", "PHONE_NUMBER", "2125551234"),
        ("Cep numaram 4155552671", "PHONE_NUMBER", "4155552671"),
        ("IP 1.2.3.4 engellendi", "IP_ADDRESS", "1.2.3.4"),
        ("gateway 10.0.0.1 down", "IP_ADDRESS", "10.0.0.1"),
        ("izin ver 10.0.0.5", "IP_ADDRESS", "10.0.0.5"),
        ("casino 4155552671", "PHONE_NUMBER", "4155552671"),
        ("John Smith 2125551234 New York", "PHONE_NUMBER", "2125551234"),
        ("Kunde Hans, 01725955200", "PHONE_NUMBER", "01725955200"),
        ("Reach me at 4155552671", "PHONE_NUMBER", "4155552671"),
        ("patient ID 12345678901", "PHONE_NUMBER", "12345678901"),
        ('{"customer_phone": 4155552671}', "PHONE_NUMBER", "4155552671"),
        ('{"x": 2125551234}', "PHONE_NUMBER", "2125551234"),
        ("contact code 4155552671", "PHONE_NUMBER", "4155552671"),
        ("https://wa.me/4155552671", "PHONE_NUMBER", "4155552671"),
        ("DNS server 8.8.8.8 is down", "IP_ADDRESS", "8.8.8.8"),
        ("release 10.20.30.40 failed", "IP_ADDRESS", "10.20.30.40"),
    ],
)
def test_phones_and_addresses_are_detected_unless_marked_otherwise(
    scrubber: PIIScrubberService,
    text: str,
    entity: str,
    value: str,
) -> None:
    assert [
        (finding["type"], text[finding["start"] : finding["end"]])
        for finding in scrubber.analyze(text, DEFAULT_ACTIONS)
    ] == [(entity, value)]


@pytest.mark.parametrize(
    "address",
    [
        "a" * 65 + "@example.com",
        "x" * 63 + ".y@example.com",
        "b" * 70 + "[at]example.com",
    ],
)
def test_a_local_part_longer_than_the_rfc_limit_is_still_masked_whole(
    scrubber: PIIScrubberService, address: str
) -> None:
    scrubbed, mapping = scrubber.scrub(f"Bilgi: {address}", DEFAULT_ACTIONS)

    assert list(mapping.values()) == [address]
    assert scrubbed == f"Bilgi: {next(iter(mapping))}"


@pytest.mark.parametrize(
    "text",
    [
        "a." * 16000 + "@",
        "a." * 16000 + " [at] ",
    ],
)
def test_adversarial_runs_stay_linear(scrubber: PIIScrubberService, text: str) -> None:
    started = time.perf_counter()
    scrubber.analyze(text, DEFAULT_ACTIONS)

    # Unbounded, the email patterns took 20 s and more on 32 KB.
    assert time.perf_counter() - started < 5


def test_a_json_document_survives_scrubbing_with_only_the_phone_replaced(
    scrubber: PIIScrubberService,
) -> None:
    document = json.dumps(
        {
            "created": 1757496600,
            "created_ms": 1757496600123,
            "elapsed": 0.0376118499,
            "mean": 0.9876543210,
            "contact": "Tel: 0212 555 12 34",
        }
    )

    scrubbed, mapping = scrubber.scrub(document, DEFAULT_ACTIONS)
    parsed = json.loads(scrubbed)

    assert list(mapping.values()) == ["0212 555 12 34"]
    assert parsed["created"] == 1757496600
    assert parsed["created_ms"] == 1757496600123
    assert parsed["elapsed"] == 0.0376118499
    assert parsed["contact"].startswith("Tel: <PHONE_NUMBER_")
    assert json.loads(scrubber.deanonymize(scrubbed, mapping)) == json.loads(document)


def test_entity_actions_follow_the_switches_and_overrides_win() -> None:
    defaults = effective_entity_actions()
    resolved = effective_entity_actions(
        {"block_email": False, "block_secrets": True},
        {"SECRET": "block", "PHONE_NUMBER": "monitor", "EMAIL_ADDRESS": "mask"},
    )

    assert set(defaults.values()) == {"mask"}
    assert len(defaults) == 13
    assert resolved["SECRET"] == "block"
    assert resolved["DB_URI"] == "mask"
    assert resolved["PHONE_NUMBER"] == "monitor"
    assert resolved["EMAIL_ADDRESS"] == "mask"
    assert effective_entity_actions({"block_email": False})["EMAIL_ADDRESS"] == "off"
    assert list(resolved) == sorted(resolved)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"PERSON": "mask"}, "unknown entity type: PERSON"),
        ({"SECRET": "warn"}, "unknown entity action: warn"),
        ({"EMAIL_ADDRESS": "mask_last4"}, "mask_last4 is only for CREDIT_CARD"),
    ],
)
def test_entity_actions_reject_unknown_types_and_actions(overrides, message) -> None:
    with pytest.raises(ValueError, match=message):
        effective_entity_actions(None, overrides)


def test_monitored_values_stay_in_place_beside_masked_ones(
    scrubber: PIIScrubberService,
) -> None:
    actions = effective_entity_actions(None, {"EMAIL_ADDRESS": "monitor"})
    iban = "TR33 0006 1005 1978 6457 8413 26"
    unmasked: dict[str, str] = {}

    scrubbed, mapping = scrubber.scrub(
        f"Mail alice@example.com, IBAN {iban}", actions, unmasked=unmasked
    )

    assert "alice@example.com" in scrubbed
    assert iban not in scrubbed
    assert list(mapping.values()) == [iban]
    assert unmasked == {"alice@example.com": "EMAIL_ADDRESS"}


def test_payload_records_monitored_and_blocked_values_without_placeholders(
    scrubber: PIIScrubberService,
) -> None:
    actions = effective_entity_actions(
        None, {"EMAIL_ADDRESS": "monitor", "SECRET": "block"}
    )
    secret = "sk-proj-" + "0" * 32
    payload = {
        "messages": [
            {"role": "user", "content": f"alice@example.com key {secret}"},
            {"role": "user", "content": "again alice@example.com"},
        ]
    }
    unmasked: dict[str, str] = {}

    safe, mapping = scrub_payload(payload, actions, scrubber, unmasked=unmasked)

    assert safe == payload
    assert mapping == {}
    assert unmasked == {"alice@example.com": "EMAIL_ADDRESS", secret: "SECRET"}


def test_analyze_reports_each_entity_action(scrubber: PIIScrubberService) -> None:
    actions = effective_entity_actions(
        {"block_phone": False}, {"EMAIL_ADDRESS": "monitor"}
    )

    findings = scrubber.analyze("alice@example.com +90 532 000 00 00", actions)

    assert [(item["type"], item["action"]) for item in findings] == [
        ("EMAIL_ADDRESS", "monitor")
    ]


_LAST4 = effective_entity_actions(
    None, {"CREDIT_CARD": "mask_last4", "IBAN_CODE": "mask_last4"}
)


@pytest.mark.parametrize(
    ("value", "entity_type", "tail"),
    [
        ("4111 1111 1111 1111", "CREDIT_CARD", "1111"),
        ("5555-5555-5555-4444", "CREDIT_CARD", "4444"),
        ("TR33 0006 1005 1978 6457 8413 26", "IBAN_CODE", "1326"),
        ("mt84 malt 0110 0001 2345 mtlc ast0 01s", "IBAN_CODE", "001S"),
    ],
)
def test_mask_last4_keeps_the_last_four_after_the_hex(
    scrubber: PIIScrubberService, value: str, entity_type: str, tail: str
) -> None:
    scrubbed, mapping = scrubber.scrub(f"Pay with {value} today", _LAST4)

    [placeholder] = mapping
    assert re.fullmatch(rf"<{entity_type}_[0-9a-f]{{32}}~{tail}>", placeholder)
    assert scrubbed == f"Pay with {placeholder} today"
    assert mapping[placeholder] == value
    assert scrubber.deanonymize(scrubbed, mapping) == f"Pay with {value} today"
    assert "~" not in next(iter(scrubber.scrub(value, DEFAULT_ACTIONS)[1]))


def test_a_tail_too_short_to_show_keeps_the_value_masked_whole() -> None:
    assert pii_scrubber_module._tail("IBAN_CODE", "T-R-3") == ""
    assert (
        pii_scrubber_module._tail("CREDIT_CARD", "４１１１ １１１１ １１１１ ４３２１")
        == "~4321"
    )


def test_a_tailed_placeholder_restores_with_or_without_its_tail_only(
    scrubber: PIIScrubberService,
) -> None:
    _, mapping = scrubber.scrub("4111 1111 1111 1111", _LAST4)
    [placeholder] = mapping
    bare = placeholder.partition("~")[0] + ">"
    wrong = placeholder.partition("~")[0] + "~9999>"

    assert scrubber.deanonymize(f"{placeholder} {bare}", mapping) == (
        "4111 1111 1111 1111 4111 1111 1111 1111"
    )
    assert scrubber.deanonymize(wrong, mapping) == wrong
    assert scrubber.deanonymize("<CREDIT_CARD_" + "0" * 32 + ">", mapping) == (
        "<CREDIT_CARD_" + "0" * 32 + ">"
    )


def test_a_tailed_placeholder_survives_every_stream_split(
    scrubber: PIIScrubberService,
) -> None:
    from shim.privacy.deanonymizer import restore_fragment

    _, mapping = scrubber.scrub("TR33 0006 1005 1978 6457 8413 26", _LAST4)
    [placeholder] = mapping
    value = mapping[placeholder]
    bare = placeholder.partition("~")[0] + ">"
    for token, expected in ((placeholder, value), (bare, value)):
        for split in range(len(token) + 1):
            buffers: dict[tuple[object, ...], str] = {}
            output = restore_fragment(buffers, (0,), token[:split], mapping, scrubber)
            output += restore_fragment(buffers, (0,), token[split:], mapping, scrubber)
            assert output == expected
            assert not buffers


def test_chat_stream_restores_a_tail_split_across_chunks(
    scrubber: PIIScrubberService,
) -> None:
    _, mapping = scrubber.scrub("4111 1111 1111 1111", _LAST4)
    [placeholder] = mapping
    restorer = OpenAIStreamRestorer(mapping, scrubber)
    split = placeholder.index("~") + 2

    chunks = [
        restorer.restore_chat_chunk(
            {
                "choices": [
                    {"index": 0, "delta": {"content": part}, "finish_reason": end}
                ]
            }
        )
        for part, end in (
            ("Card " + placeholder[:split], None),
            (placeholder[split:] + ".", "stop"),
        )
    ]

    assert "".join(chunk["choices"][0]["delta"]["content"] for chunk in chunks) == (
        "Card 4111 1111 1111 1111."
    )


def test_json_restoration_resolves_tailed_placeholders(
    scrubber: PIIScrubberService,
) -> None:
    _, mapping = scrubber.scrub("TR33 0006 1005 1978 6457 8413 26", _LAST4)
    [placeholder] = mapping
    bare = placeholder.partition("~")[0] + ">"
    payload = {
        "id": placeholder,
        "content": [{"type": "text", "text": f"{placeholder} {bare}"}],
    }

    restored = restore_anthropic_payload(payload, mapping, scrubber)

    assert restored["id"] == placeholder
    assert restored["content"][0]["text"] == (
        "TR33 0006 1005 1978 6457 8413 26 TR33 0006 1005 1978 6457 8413 26"
    )


_ROOT = b"r" * 32
_AT = datetime(2026, 10, 8, tzinfo=timezone.utc)


def test_stable_placeholders_follow_tenant_and_period(
    scrubber: PIIScrubberService,
) -> None:
    def placeholder(tenant: str, at: datetime) -> str:
        key = placeholder_period_key(_ROOT, tenant, at)
        return next(
            iter(
                scrubber.scrub(
                    "alice@example.com", DEFAULT_ACTIONS, placeholder_key=key
                )[1]
            )
        )

    first = placeholder("tenant-a", _AT)
    period = 2_592_000
    start = datetime.fromtimestamp(
        int(_AT.timestamp()) // period * period, timezone.utc
    )
    digest = hmac.new(
        hmac.new(
            _ROOT,
            f"shim.placeholder.v1\x1ftenant-a\x1f{int(_AT.timestamp()) // period}".encode(),
            hashlib.sha256,
        ).digest(),
        b"EMAIL_ADDRESS\x1falice@example.com",
        hashlib.sha256,
    ).hexdigest()

    assert first == f"<EMAIL_ADDRESS_{digest[:32]}>"
    assert placeholder("tenant-a", start) == first
    assert placeholder("tenant-a", start + timedelta(days=30, seconds=-1)) == first
    assert placeholder("tenant-a", start + timedelta(days=30)) != first
    assert placeholder("tenant-b", _AT) != first


def test_stable_mode_keeps_the_tail_and_two_spellings_apart(
    scrubber: PIIScrubberService,
) -> None:
    key = placeholder_period_key(_ROOT, "tenant-a", _AT)
    spaced, compact = "TR33 0006 1005 1978 6457 8413 26", "TR330006100519786457841326"

    _, first = scrubber.scrub(f"{spaced} {compact}", _LAST4, placeholder_key=key)
    _, again = scrubber.scrub(spaced, _LAST4, placeholder_key=key)

    assert [placeholder[-6:] for placeholder in first] == ["~1326>", "~1326>"]
    assert len(set(first)) == 2
    assert next(iter(again)) == next(iter(first))


def test_a_stable_placeholder_held_by_another_value_falls_back_to_random(
    scrubber: PIIScrubberService,
) -> None:
    key = placeholder_period_key(_ROOT, "tenant-a", _AT)
    [derived] = scrubber.scrub(
        "alice@example.com", DEFAULT_ACTIONS, placeholder_key=key
    )[1]

    scrubbed, mapping = scrubber.scrub(
        "alice@example.com",
        DEFAULT_ACTIONS,
        known_placeholders={derived: "bob@example.com"},
        placeholder_key=key,
    )

    [fallback] = mapping
    assert fallback != derived and fallback.startswith("<EMAIL_ADDRESS_")
    assert mapping[fallback] == "alice@example.com"
    assert scrubber.deanonymize(scrubbed, {derived: "bob@example.com", **mapping}) == (
        "alice@example.com"
    )


def _answered(**privacy) -> SimpleNamespace:
    return SimpleNamespace(
        pii_config=None,
        entity_actions={"PHONE_NUMBER": "off"},
        privacy=PrivacyOutcome(
            action=PrivacyAction.SCRUBBED, pii_detected=True, **privacy
        ),
    )


def test_a_response_scan_counts_new_values_once_and_never_the_callers_own(
    scrubber: PIIScrubberService,
) -> None:
    iban = "TR33 0006 1005 1978 6457 8413 26"
    prepared = _answered(
        verification_map={"<IBAN_CODE_" + "0" * 32 + ">": iban},
        monitored_values=frozenset({"own@example.com"}),
    )
    answer = (
        f"Your IBAN {iban.replace(' ', '')} and own@example.com. New: TCKN 10000000146, "
        "new@example.com, again new@example.com, IBAN GB82 WEST 1234 5698 7654 32, "
        "phone +90 532 000 00 00"
    )

    assert scan_response(answer, prepared, scrubber) == {
        "response_entities": {"EMAIL_ADDRESS": 1, "IBAN_CODE": 1, "TR_NATIONAL_ID": 1},
        "truncated": False,
    }
    assert scan_response("", prepared, scrubber) == {
        "response_entities": {},
        "truncated": False,
    }


def test_a_response_scan_reads_only_up_to_the_analyzer_limit(
    scrubber: PIIScrubberService, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(privacy_module, "MAX_ANALYZABLE_TEXT_LENGTH", 40)
    head = "Write to new@example.com."

    assert scan_response(head.ljust(40), _answered(), scrubber)["truncated"] is False
    assert scan_response(head.ljust(41), _answered(), scrubber) == {
        "response_entities": {"EMAIL_ADDRESS": 1},
        "truncated": True,
    }
    assert scan_response("x" * 40 + head, _answered(), scrubber) == {
        "response_entities": {},
        "truncated": True,
    }


_NESTED_EMAIL = "Open /home/alice/john.doe@example.com/notes.txt please"


@pytest.mark.parametrize(
    ("overrides", "masked", "kept"),
    [
        ({"FILE_PATH": "monitor"}, ["EMAIL_ADDRESS"], []),
        ({"FILE_PATH": "monitor", "EMAIL_ADDRESS": "block"}, [], ["EMAIL_ADDRESS"]),
        ({"EMAIL_ADDRESS": "block"}, [], ["EMAIL_ADDRESS"]),
    ],
)
def test_the_stronger_action_wins_an_overlap(
    scrubber: PIIScrubberService,
    overrides: dict[str, str],
    masked: list[str],
    kept: list[str],
) -> None:
    unmasked: dict[str, str] = {}

    scrubbed, mapping = scrubber.scrub(
        _NESTED_EMAIL, effective_entity_actions(None, overrides), unmasked=unmasked
    )

    assert [placeholder[1:].rpartition("_")[0] for placeholder in mapping] == masked
    assert list(unmasked.values()) == kept
    assert all("john.doe@example.com" in value for value in unmasked)
    if masked:
        assert "john.doe@example.com" not in scrubbed
