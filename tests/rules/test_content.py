from __future__ import annotations

import random
import timeit

import pytest

import shim.rules.content as content
from shim.rules import RuleSetError, validate_rule_set
from shim.rules.content import (
    ContentHit,
    count_rule_matches,
    first_fit,
    turkish_fold,
)
from shim.rules.patterns import PatternTimeout
from shim.rules.tr_suffixes import TR_SUFFIX, TR_SUFFIXES_VERSION


def _rule(rule_id: str = "words", kind: str = "term", **values) -> dict:
    return {
        "id": rule_id,
        "name": "n",
        "kind": kind,
        "action": "mask",
        "state": "monitor",
        **values,
    }


def _term(*terms: str, rule_id: str = "words", **match) -> dict:
    return _rule(rule_id, match={"terms": list(terms), **match})


def _pattern(rule_id: str = "codes", **match) -> dict:
    return _rule(rule_id, "pattern", match=match)


def _set(*rules: dict):
    return validate_rule_set({"revision": 1, "rules": list(rules)})


def _refused(*rules: dict) -> tuple[str, str]:
    with pytest.raises(RuleSetError) as error:
        _set(*rules)
    return error.value.code, error.value.path


def _found(rule: dict, text: str) -> int:
    return count_rule_matches(_set(rule), text)[rule["id"]]


@pytest.mark.parametrize(
    ("match", "path"),
    [
        ({"terms": ["ab"]}, "rules[0].match.terms[0]"),
        ({"terms": ["+++"]}, "rules[0].match.terms[0]"),
        ({"terms": ["x" * 129]}, "rules[0].match.terms[0]"),
        ({"terms": ["İzmir", "IZMIR"]}, "rules[0].match.terms"),
        ({"terms": []}, "rules[0].match.terms"),
        ({"terms": ["Atlas"], "label": "term"}, "rules[0].match.label"),
        ({"terms": ["Atlas"], "label": "T"}, "rules[0].match.label"),
        ({"terms": ["Atlas"], "label": "EMAIL_ADDRESS"}, "rules[0].match.label"),
        ({"terms": ["Atlas"], "label": "PERSON"}, "rules[0].match.label"),
        ({"terms": ["Atlas"], "suffixes": "en"}, "rules[0].match.suffixes"),
    ],
)
def test_a_term_match_is_refused_with_its_path(match, path) -> None:
    assert _refused(_rule(match=match)) == ("RULE_MATCH_INVALID", path)


def test_terms_are_trimmed_and_keep_one_space() -> None:
    stored = _set(_term("  İzmir \t Proje  ", "ＡＴＬＡＳ")).rules[0].match

    assert stored == {
        "terms": ["İzmir Proje", "ATLAS"],
        "label": "TERM",
        "suffixes": "tr",
    }


@pytest.mark.parametrize(
    ("match", "code", "path"),
    [
        ({}, "RULE_MATCH_INVALID", "rules[0].match"),
        (
            {"templates": ["x" * 65]},
            "RULE_MATCH_INVALID",
            "rules[0].match.templates[0]",
        ),
        ({"templates": ["PRJ\\"]}, "RULE_MATCH_INVALID", "rules[0].match.templates[0]"),
        ({"regexes": ["(a+)+$"]}, "RULE_PATTERN_UNSAFE", "rules[0].match.regexes[0]"),
        ({"regexes": ["(a)\\1"]}, "RULE_PATTERN_UNSAFE", "rules[0].match.regexes[0]"),
        ({"regexes": ["("]}, "RULE_PATTERN_UNSAFE", "rules[0].match.regexes[0]"),
        ({"regexes": ["x" * 257]}, "RULE_MATCH_INVALID", "rules[0].match.regexes[0]"),
        ({"templates": ["#"] * 33}, "RULE_MATCH_INVALID", "rules[0].match.templates"),
    ],
)
def test_a_pattern_match_is_refused_with_its_path(match, code, path) -> None:
    assert _refused(_rule("codes", "pattern", match=match)) == (code, path)


def test_a_set_holds_at_most_2000_terms_64_regexes_and_64_templates() -> None:
    terms = [
        _term(
            *(f"term{rule:02d}x{index:03d}" for index in range(200)), rule_id=f"t{rule}"
        )
        for rule in range(10)
    ]
    regexes = [
        _pattern(f"p{rule}", regexes=[f"code{rule}-{index}" for index in range(32)])
        for rule in range(2)
    ]

    _set(*terms, *regexes)
    assert _refused(*terms, _term("one more", rule_id="extra")) == (
        "RULE_SET_INVALID",
        "rules[10].match.terms",
    )
    assert _refused(*regexes, _pattern("extra", regexes=["x"])) == (
        "RULE_SET_INVALID",
        "rules[2].match.regexes",
    )
    templates = [
        _pattern(
            f"t{rule}", templates=[f"T{rule}-{index:02d}-#" for index in range(32)]
        )
        for rule in range(2)
    ]
    _set(*templates)
    assert _refused(*templates, _pattern("extra", templates=["X-#"])) == (
        "RULE_SET_INVALID",
        "rules[2].match.templates",
    )


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("PRJ-1234", 1),
        ("prj-1234", 1),
        ("see PRJ-1234.", 1),
        ("PRJ-12345", 0),
        ("XPRJ-1234", 0),
        ("PRJ-123", 0),
    ],
)
def test_a_template_matches_its_shape_between_boundaries(text, found) -> None:
    assert _found(_pattern(templates=["PRJ-####"]), text) == found


def test_template_letters_literals_and_case() -> None:
    assert _found(_pattern(templates=["@@-##"]), "AB-12 ç-1 Çş-34") == 2
    assert _found(_pattern(templates=["\\#\\@-#"]), "#@-7 ab-7") == 1
    assert _found(_pattern(templates=["PRJ-#"], ignore_case=False), "prj-1 PRJ-2") == 1


def test_a_regex_runs_as_written() -> None:
    assert _found(_pattern(regexes=[r"INV\d{6}"]), "inv123456 INV654321") == 2
    assert _found(_pattern(regexes=[r"INV\d{6}"], ignore_case=False), "inv123456") == 0


@pytest.mark.parametrize(
    ("term", "text"),
    [
        ("İzmir Proje", "IZMIR PROJE"),
        ("İzmir Proje", "ıZMİR PROJE"),
        ("İzmir Proje", "izmir  proje"),
        ("Irmak", "ırmak"),
        ("Irmak", "İRMAK"),
        ("ırmak", "IRMAK"),
        ("Şişli Kule", "ŞİŞLİ KULE"),
    ],
)
def test_the_four_i_letters_match_each_other(term, text) -> None:
    assert _found(_term(term), text) == 1


def test_the_turkish_fold() -> None:
    assert turkish_fold("İZMİR  Proje") == turkish_fold("ızmır proje") == "izmir proje"


@pytest.mark.parametrize(
    ("text", "found"),
    [
        ("Atlas'ın", 1),
        ("Atlas’tan", 1),
        ("Atlas‘a", 1),
        ("Atlasʼa", 1),
        ("Atlasın", 1),
        ("Atlasları", 1),
        ("Atlaslarından", 1),
        ("ATLASIN", 1),
        ("Atlasçılık", 0),
        ("Atlasx", 0),
        ("XAtlas", 0),
    ],
)
def test_turkish_suffixes_follow_the_closed_list(text, found) -> None:
    assert _found(_term("Atlas"), text) == found


def test_short_terms_and_suffixes_none_take_no_suffix() -> None:
    short = _term("Ata")
    assert [
        _found(short, text) for text in ("Ata", "Ata'nın", "Ataʼnın", "Atalar", "Atada")
    ] == [1, 1, 1, 0, 0]
    plain = _term("Atlas", suffixes="none")
    assert [
        _found(plain, text) for text in ("Atlas", "Atlas'ın", "Atlasın", "Atlasʼa")
    ] == [1, 1, 0, 0]


def test_only_the_term_is_the_match_and_the_longest_term_wins() -> None:
    rule_set = _set(_term("Atlas", "Atlas Proje"))
    found = content.content_rules(rule_set, lambda _rule: True)
    assert found is not None

    hits = first_fit(
        found.search("Atlasın raporu, Atlas Projesi"),
        key=lambda hit: (hit.start - hit.end, hit.start),
    )

    assert sorted((hit.start, hit.end) for hit in hits) == [(0, 5), (16, 27)]


def test_two_rules_listing_one_term_both_count_it() -> None:
    assert count_rule_matches(
        _set(_term("Atlas", rule_id="one"), _term("ATLAS", rule_id="two")), "atlas'ın"
    ) == {"one": 1, "two": 1}


def test_the_suffix_grammar_keeps_every_version_1_ending() -> None:
    def expand(template: str) -> set[str]:
        # A = a/e; I = ı/u (back) or i/ü (front), only ı/i after the plural; D = d/t.
        plural = "lAr" in template
        return {
            template.replace("A", a).replace("I", i).replace("D", d)
            for a, vowels in (
                ("a", "ı" if plural else "ıu"),
                ("e", "i" if plural else "iü"),
            )
            for i in vowels
            for d in ("dt" if template.startswith("D") else "d")
        }

    single = [
        "lAr",
        "I",
        "sI",
        "lArI",
        "yI",
        "A",
        "yA",
        "DA",
        "DAn",
        "In",
        "nIn",
        "lA",
        "ylA",
        "DAki",
    ]
    plural_case = ["lArA", "lArdA", "lArdAn", "lArIn", "lArlA", "lArdAki"]
    possessive_case = [
        buffer + case
        for buffer in ("", "s")
        for case in ("InI", "InA", "IndA", "IndAn", "InIn", "IylA", "IndAki")
    ]
    plural_possessive_case = [
        "lArInI",
        "lArInA",
        "lArIndA",
        "lArIndAn",
        "lArInIn",
        "lArIylA",
    ]
    expected = {
        suffix
        for template in single + plural_case + possessive_case + plural_possessive_case
        for suffix in expand(template)
        if len(suffix) <= 8
    }

    # The 124 endings version 1 listed, each at most eight characters.
    assert len(expected) == 124
    assert TR_SUFFIXES_VERSION == 2
    assert [
        suffix for suffix in expected if not TR_SUFFIX.fullmatch(content._fold(suffix))
    ] == []
    assert not any(
        TR_SUFFIX.fullmatch(content._fold(derived))
        for derived in ("çılık", "cı", "lık", "sız", "siz", "li", "dibi", "ian", "x")
    )


def test_a_rule_set_compiles_once_per_object(monkeypatch) -> None:
    built = []

    class Counted(content.Matchers):
        def __init__(self, rule_set) -> None:
            built.append(rule_set)
            super().__init__(rule_set)

    monkeypatch.setattr(content, "Matchers", Counted)
    first, second = _set(_term("Atlas")), _set(_term("Atlas"))

    for rule_set in (first, first, second):
        count_rule_matches(rule_set, "Atlas")

    assert built == [first, second] and built[0] is first


def test_counting_ignores_state_scope_and_action_and_skips_other_kinds() -> None:
    rule_set = _set(
        _term("Atlas", rule_id="monitored"),
        {
            **_term("Atlas", rule_id="elsewhere"),
            "state": "monitor",
            "action": "block",
            "scope": {"models": ["no-such-model"]},
        },
        _pattern(templates=["PRJ-####"]),
    )
    record_set = rule_set.rules[0].model_copy(
        update={"id": "records", "kind": "record_set"}
    )
    rule_set = rule_set.model_copy(update={"rules": (*rule_set.rules, record_set)})

    counts = count_rule_matches(rule_set, "Atlas, ATLAS'ın, PRJ-1234, PRJ-1234")

    assert counts == {"monitored": 2, "elsewhere": 2, "codes": 1}
    assert all(isinstance(value, int) for value in counts.values())


def test_a_search_that_times_out_counts_minus_one(monkeypatch) -> None:
    searched = content.SearchBudget.finditer

    def finditer(self, pattern, text):
        if "INV" in pattern.pattern:
            raise PatternTimeout
        return searched(self, pattern, text)

    monkeypatch.setattr(content.SearchBudget, "finditer", finditer)

    assert count_rule_matches(
        _set(_term("Atlas"), _pattern(regexes=[r"INV\d+"])), "Atlas INV1"
    ) == {"words": 1, "codes": -1}


def test_a_span_found_by_several_rules_is_one_hit_with_every_rule() -> None:
    found = content.content_rules(
        _set(
            _pattern("one", regexes=[r"PRJ-\d+"]),
            _pattern("two", templates=["PRJ-####"]),
        ),
        lambda _rule: True,
    )
    assert found is not None

    [hit] = found.search("PRJ-1234")

    assert (hit.start, hit.end, [rule.id for rule in hit.rules]) == (
        0,
        8,
        ["one", "two"],
    )


def test_first_fit_takes_spans_in_key_order_and_kept_ones_always() -> None:
    one, two = _set(_term("Atlas", rule_id="one"), _term("Heron", rule_id="two")).rules
    hits = [
        ContentHit(0, 5, (one,)),
        ContentHit(2, 9, (two,)),
        ContentHit(10, 14, (one,)),
        ContentHit(12, 16, (one,)),
    ]

    def longer_first(hit):
        return (hit.start - hit.end, hit.start)

    assert [(hit.start, hit.end) for hit in first_fit(hits, key=longer_first)] == [
        (2, 9),
        (10, 14),
    ]
    assert [
        (hit.start, hit.end)
        for hit in first_fit(hits, key=longer_first, keep=lambda hit: hit.start == 0)
    ] == [(2, 9), (0, 5), (10, 14)]


@pytest.mark.parametrize(
    ("term", "text"),
    [
        # Typed without Turkish letters.
        ("Şişli Kule", "SISLI KULE"),
        ("Işık Holding", "Isik Holding"),
        ("İzmir Proje", "izmir proje"),
        ("Gülçiçek", "gulcicek'in"),
        # The dotted i of a lower-cased İ (i and U+0307).
        ("İzmir Proje", "i̇zmir proje"),
        # Possessives, copula, equative, -ki, and long chains.
        ("Atlas", "Atlasımız"),
        ("Atlas", "Atlasımızın"),
        ("Atlas", "Atlasınız"),
        ("Atlas", "Atlasım"),
        ("Kule", "Kulemiz"),
        ("Kule", "Kulen"),
        ("Atlas", "Atlastır"),
        ("Atlas", "Atlaslardır"),
        ("Atlas", "Atlasça"),
        ("Atlas", "Atlasınki"),
        ("Atlas", "Atlaslarındaki"),
        ("Atlas", "Atlaslarımızdakiler"),
        ("Atlas", "Atlastakini"),
        ("Atlas", "Atlasındadır"),
        # A short term in capitals takes a lower-case ending without an apostrophe.
        ("BKM", "BKMnin"),
        ("BKM", "BKMye"),
        ("BKM", "BKMninRaporu"),
        ("e-Devlet", "yeniE-Devlet"),
        # Word edges: underscore, letter and digit, lower to upper case.
        ("Atlas", "atlas_rapor.xlsx"),
        ("Atlas", "Atlas2024"),
        ("Atlas", "AtlasProje"),
        # Other dashes are a hyphen.
        ("e-Devlet", "e–Devlet"),
        ("e-Devlet", "e‐Devlet'e"),
        ("PRJ-2024-001", "PRJ−2024−001"),
    ],
)
def test_a_term_is_found_in_every_form_it_is_written_in(term, text) -> None:
    assert _found(_term(term), text) == 1


@pytest.mark.parametrize(
    ("term", "text"),
    [
        ("Atlas", "Atlasçılık"),
        ("Atlas", "Atlasian"),
        ("Atlas", "XAtlas"),
        ("Kule", "Kuleli"),
        ("Kule", "Kulesiz"),
        ("Kule", "Kuledibi"),
        ("PRJ-2024-001", "PRJ-2024-0012"),
        ("Ata", "Atalar"),
        ("Ata", "ATALAR"),
        ("Ata", "Atada"),
        ("BKM", "BKMNIN"),
    ],
)
def test_a_longer_word_is_not_the_term(term, text) -> None:
    assert _found(_term(term), text) == 0


@pytest.mark.parametrize("text", ["PRJ–1234", "PRJ−1234", "prj‐1234"])
def test_a_template_hyphen_takes_any_dash(text) -> None:
    assert _found(_pattern(templates=["PRJ-####"]), text) == 1


def test_the_matcher_stays_fast_at_the_set_limits() -> None:
    # 2,000 terms, a fifth of them sharing their first word, and 32 KB made only of
    # their words with endings, so every word starts a walk through the index.
    rng = random.Random(7)
    syllables = "ka ra de ni şe hi ğu çe kö ip ür sel tan bey gül fır".split()
    words = sorted(
        {
            "".join(rng.choice(syllables) for _ in range(3)).capitalize()
            for _ in range(4_000)
        }
    )[:1_600]
    terms = words + [f"Atlas {word}" for word in words[:400]]
    rule_set = _set(
        *(
            _term(*terms[i : i + 200], rule_id=f"r{i // 200}")
            for i in range(0, 2_000, 200)
        )
    )
    text = " ".join(
        rng.choice(["Atlas", *terms]) + rng.choice(["", "'ın", "ları", "da", "ndan"])
        for _ in range(4_000)
    )[:32_768]
    found = content.content_rules(rule_set, lambda _rule: True)
    assert found is not None and len(found.search(text)) > 2_000

    elapsed = min(timeit.repeat(lambda: found.search(text), number=1, repeat=3))

    assert elapsed < 0.05
