from __future__ import annotations

import hashlib
import re
from pathlib import Path

from shim.privacy.pii_scrubber import PIIScrubberService
from shim.privacy.policies import effective_entity_actions
from shim.rules.content import turkish_fold
from shim_enterprise.rules import proposals

DATA = Path(proposals.__file__).parent
# Changing the corpus changes what too_broad means: bump PROPOSAL_CHECKS_VERSION.
CORPUS_SHA256 = "1538b3b4cf29c3b67a6b6fbbc5a294b1ea0ba0a35648c4e19fd915ae16813bda"


def test_the_stoplist_is_large_and_has_no_duplicate_after_the_fold() -> None:
    words = (DATA / "proposal_stoplist.txt").read_text("utf-8").split()
    folded = [turkish_fold(word) for word in words]

    assert len(words) >= 120
    assert len(folded) == len(set(folded))
    for generic in ("gizli", "müşteri", "confidential", "customer", "strateji"):
        assert turkish_fold(generic) in folded


def test_the_corpus_is_long_neutral_and_pinned() -> None:
    raw = (DATA / "proposal_corpus.txt").read_bytes()
    text = raw.decode("utf-8")
    actions = {kind: "mask" for kind in effective_entity_actions()}

    assert len(text.split()) >= 3000
    assert hashlib.sha256(raw).hexdigest() == CORPUS_SHA256
    assert proposals.PROPOSAL_CHECKS_VERSION == 1
    assert not re.search(r"[A-Za-z]+-\d", text)
    assert PIIScrubberService().analyze(text, actions) == []
