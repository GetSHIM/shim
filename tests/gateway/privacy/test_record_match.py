import json
from pathlib import Path
import random
import tracemalloc

import pytest

from shim.privacy import record_match
from shim.privacy.record_match import (
    RecordField,
    RecordSetIndex,
    fingerprints,
    normalize,
    record_hash,
)
from shim.rules import Rule, RuleSet
from shim.rules.content import ContentRules
from shim.rules.patterns import SearchBudget

KEY = bytes(range(32))


@pytest.mark.parametrize(
    ("kind", "value", "normal", "pinned"),
    [
        ("tckn", " 100 000 00146 ", "10000000146", 3971112380328410384),
        ("vkn", "1234567890", "1234567890", 11841021375613267742),
        (
            "iban",
            "tr33 0006 1005 1978 6457 8413 26",
            "TR330006100519786457841326",
            17672837402056199967,
        ),
        (
            "email",
            " Ayse.Yilmaz@Example.COM ",
            "ayse.yilmaz@example.com",
            13576062874991464451,
        ),
        ("phone", "+90 (532) 123 45 67", "5321234567", 11734157253286110798),
        ("digits", "00123456", "00123456", 5871788764937944296),
        ("token", "mus-000123", "MUS-000123", 3636328146560824745),
        ("name", "  İSMAİL   Işık ", "ismail işik", 12488803229028907849),
    ],
)
def test_each_kind_has_one_normal_form_and_a_stable_hash(
    kind, value, normal, pinned
) -> None:
    length = (6, 12) if kind == "digits" else None

    assert normalize(kind, value, length) == normal
    # The hashing tool and the gateway must agree byte for byte, release after release.
    assert record_hash(KEY, kind, normal) == pinned


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("tckn", "1000000014"),
        ("iban", "DE89370400440532013000"),
        ("email", "not-an-email"),
        ("phone", "12345"),
        ("token", "ab"),
        ("name", "bir iki üç dört"),
    ],
)
def test_a_value_of_another_shape_has_no_normal_form(kind, value) -> None:
    assert normalize(kind, value) is None


def test_fingerprints_of_a_pinned_text_and_the_rightmost_tie() -> None:
    text = (
        "Bu sözleşme gizlidir ve taraflar arasında imzalanan hizmet koşullarını "
        "içerir; üçüncü kişilerle paylaşılamaz."
    )

    assert sorted(fingerprints(KEY, text)) == [1910190035016085801, 2930848871746140097]
    assert fingerprints(KEY, "kısa bir metin") == set()
    # Twelve identical words: every shingle hashes alike and one is chosen.
    assert len(fingerprints(KEY, "aynı " * 12)) == 1


def _customers(count: int = 1_000) -> RecordSetIndex:
    fields = (
        RecordField("token", primary=True),
        RecordField("name"),
        RecordField("tckn", primary=True),
        RecordField("iban"),
        RecordField("email"),
    )
    rows = []
    for number in range(count):
        values = [
            ("token", f"MUS{number:06d}"),
            ("name", "İsmail Işık" if number == 7 else f"Müşteri {number}"),
            ("tckn", "10000000146" if number == 7 else ""),
            ("iban", "TR330006100519786457841326" if number == 7 else ""),
            ("email", "ismail@example.com" if number == 7 else ""),
        ]
        rows.append(
            [
                record_hash(KEY, kind, normalized)
                if (normalized := normalize(kind, value))
                else 0
                for kind, value in values
            ]
        )
    return RecordSetIndex.records(KEY, fields, rows)


@pytest.mark.parametrize(
    ("text", "min_fields", "matched"),
    [
        ("Müşteri MUS000007 hakkında not", 2, set()),
        ("Müşteri MUS000007 hakkında not", 1, {7}),
        ("Müşteri MUS000007: ismail IŞIK aradı.", 2, {7}),
        ("TCKN 10000000146 ve IBAN tr33 0006 1005 1978 6457 8413 26", 2, {7}),
        ("ISMAIL@EXAMPLE.COM yazdı, müşteri no MUS000007", 2, {7}),
        ("Müşteri MUS000007" + " dolgu" * 80 + " İsmail Işık", 2, set()),
        ("Müşteri MUS000008 ve İsmail Işık", 2, set()),
    ],
)
def test_a_record_matches_when_enough_of_its_fields_appear_near_a_primary(
    text, min_fields, matched
) -> None:
    found, spans, truncated = _customers().match_records(text, min_fields)

    assert (found, truncated) == (matched, False)
    assert all(0 <= start < end <= len(text) for start, end in spans)


def test_candidates_stop_at_the_cap_and_say_so(monkeypatch) -> None:
    monkeypatch.setattr(record_match, "MAX_CANDIDATES", 3)
    text = " ".join(f"MUS{number:06d}" for number in range(10))

    found, _, truncated = _customers().match_records(text, 1)

    assert truncated and len(found) == 3


def _document(seed: int, words: int = 120) -> str:
    rng = random.Random(seed)
    vocabulary = [
        "sözleşme", "taraf", "hizmet", "bedel", "gizli", "teslim", "süre", "fesih",
        "ödeme", "fatura", "madde", "yükümlülük", "veri", "rapor", "proje", "ekip",
        "müşteri", "şirket", "onay", "imza", "tarih", "kapsam", "risk", "denetim",
    ]  # fmt: skip
    return " ".join(rng.choice(vocabulary) for _ in range(words))


@pytest.mark.parametrize(
    ("paste", "matched"),
    [
        (lambda doc: doc[: len(doc) // 2], {0}),
        (
            lambda doc: " ".join(
                "değişti" if position % 10 == 5 else word
                for position, word in enumerate(doc.split())
            ),
            {0},
        ),
        (
            lambda doc: " ".join(doc.split()[60:] + doc.split()[:60]),
            {0},
        ),
        (lambda doc: _document(99), set()),
    ],
)
def test_a_pasted_fragment_of_a_document_matches_and_unrelated_text_does_not(
    paste, matched
) -> None:
    documents = [_document(seed) for seed in range(3)]
    index = RecordSetIndex.documents(KEY, [fingerprints(KEY, doc) for doc in documents])

    assert index.match_documents(paste(documents[0]), 6) == matched
    assert index.match_documents("kırk kelimeden kısa bir metin", 2) == set()


def test_a_quarter_million_records_fit_in_twenty_megabytes() -> None:
    fields = (RecordField("token", primary=True),) + tuple(
        RecordField("digits", length=(6, 12)) for _ in range(5)
    )
    tracemalloc.start()
    try:
        index = RecordSetIndex.records(
            KEY,
            fields,
            (
                [record_hash(KEY, "token", f"T{number:08d}")]
                + [number * 7 + extra + 1 for extra in range(5)]
                for number in range(250_000)
            ),
        )
        current, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert index.size == 1_500_000
    assert current < 20_000_000


def _rules(*rules: Rule) -> RuleSet:
    return RuleSet(revision=1, rules=rules)


def _record_rule(action="block", state="enforced", **match) -> Rule:
    return Rule(
        id="customers",
        name="customers",
        kind="record_set",
        action=action,
        state=state,
        match={
            "set_id": "00000000-0000-0000-0000-000000000051",
            "min_fields": None,
            "min_shared": None,
            **match,
        },
    )


def test_the_content_rules_count_records_and_label_their_spans() -> None:
    rule = _record_rule(action="mask")
    content = ContentRules(
        _rules(rule),
        (rule,),
        record_sets={"00000000-0000-0000-0000-000000000051": _customers()},
    )

    hits = content.search("Müşteri MUS000007: İsmail Işık aradı.")

    assert content.values == {"customers": {"7"}}
    assert {hit.label for hit in hits} == {"RECORD"}


def test_a_missing_set_or_a_spent_budget_is_an_evaluation_error() -> None:
    rule = _record_rule()
    missing = ContentRules(_rules(rule), (rule,))
    spent = ContentRules(
        _rules(rule),
        (rule,),
        budget=SearchBudget(0),
        record_sets={"00000000-0000-0000-0000-000000000051": _customers()},
    )

    assert missing.search("MUS000007 İsmail Işık") == []
    assert spent.search("MUS000007 İsmail Işık") == []
    assert missing.errors == spent.errors == {"customers"}


_CORPUS = Path(__file__).parent / "corpus" / "record-sets-v2.json"


def _corpus_index(fixture: dict) -> RecordSetIndex:
    """The set as the hashing tool builds it from the checked-in CSV and a fixed key."""
    import csv

    key = bytes.fromhex(fixture["key_hex"])
    fields = tuple(RecordField(**field) for field in fixture["fields"])
    with (_CORPUS.parent / fixture["csv"]).open(encoding="utf-8") as handle:
        rows = list(csv.reader(handle))[1:]
    hashed = [
        [
            record_hash(key, field.kind, normalized)
            if (normalized := normalize(field.kind, value, field.length))
            else 0
            for field, value in zip(fields, row, strict=True)
        ]
        for row in rows
    ]
    return RecordSetIndex.records(key, fields, hashed)


@pytest.mark.parametrize(
    "case", json.loads(_CORPUS.read_text())["cases"], ids=lambda case: case["id"]
)
def test_the_record_set_corpus(case) -> None:
    corpus = json.loads(_CORPUS.read_text())
    index = _corpus_index(corpus["set"])

    found, _, _ = index.match_records(case["text"], case["min_fields"])

    assert sorted(found) == case["expect_records"]
