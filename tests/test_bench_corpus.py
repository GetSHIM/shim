"""The benchmark corpus is what it claims: valid identifiers, exact spans, one output."""

from __future__ import annotations

import random

from presidio_analyzer.predefined_recognizers import (
    CreditCardRecognizer,
    IbanRecognizer,
    TrNationalIdRecognizer,
)

from scripts.bench import pii_corpus
from scripts.bench.pii_score import leaked
from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import effective_entity_actions


def test_identifiers_pass_independent_checksums() -> None:
    rng = random.Random(1)
    tckn, iban, card = (
        TrNationalIdRecognizer(),
        IbanRecognizer(),
        CreditCardRecognizer(),
    )
    for _ in range(200):
        assert tckn.validate_result(pii_corpus.tckn(rng))
        assert iban.validate_result(pii_corpus.iban(rng).replace(" ", ""))
        assert card.validate_result(
            "".join(c for c in pii_corpus.card(rng) if c.isdigit())
        )
    # python-stdnum's published example (4540536920), and 1234567890.
    assert pii_corpus.vkn_check("454053692") == "0"
    assert pii_corpus.vkn_check("123456789") == "0"


def test_hard_negatives_fail_their_checksums() -> None:
    rng = random.Random(2)
    for _ in range(200):
        order = pii_corpus.SLOTS["order_no"][1](rng)
        invoice = pii_corpus.SLOTS["invoice_no"][1](rng)
        assert pii_corpus.tckn_check(order[:9]) != order[9:]
        assert pii_corpus.vkn_check(invoice[:9]) != invoice[9]


def test_corpus_spans_are_exact_and_output_is_deterministic(tmp_path) -> None:
    rows = [pii_corpus.render(t, random.Random(3)) for t in pii_corpus.TEMPLATES]
    for row in rows:
        for span in row["spans"]:
            value = row["text"][span["start"] : span["end"]]
            assert value and value == value.strip()
    first = pii_corpus.write(tmp_path / "a.jsonl", rows)
    again = [pii_corpus.render(t, random.Random(3)) for t in pii_corpus.TEMPLATES]
    assert pii_corpus.write(tmp_path / "b.jsonl", again) == first


def test_every_disguise_is_undone_by_the_leak_check() -> None:
    for case in pii_corpus.evasion_cases(random.Random(4), per_cell=3):
        body = [{"messages": [{"role": "user", "content": case["text"]}]}]
        assert leaked(case["spans"][0]["value"], body), case["id"]
        masked = [{"messages": [{"role": "user", "content": "<TR_NATIONAL_ID_1>"}]}]
        assert not leaked(case["spans"][0]["value"], masked)


def test_github_tokens_sit_where_only_the_token_rule_finds_them() -> None:
    # A stand-in no token rule knows, with a digit as a spaced password needs: if the
    # context alone masks it ("GITHUB_TOKEN=", "Authorization: token"), the corpus
    # would score the context, not the token rule.
    scrubber = PIIScrubberService()
    actions = effective_entity_actions(None, None)
    placed = 0
    for template in pii_corpus.TEMPLATES:
        row = pii_corpus.render(template, random.Random(5))
        for span in row["spans"]:
            if span["label"] != "GITHUB_TOKEN":
                continue
            start, end = span["start"], span["end"]
            stand_in = ("x9" * end)[: end - start]
            text = row["text"][:start] + stand_in + row["text"][end:]
            assert not [
                finding
                for finding in scrubber.analyze(text, actions)
                if finding["start"] < end and start < finding["end"]
            ], template
            placed += 1
    assert placed == 2
