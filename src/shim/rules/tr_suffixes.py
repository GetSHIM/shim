"""The Turkish endings a tenant term may carry without an apostrophe (version 2).

A grammar over the folded text (ı and i as i, ü and u as u, ç as c, lower case), so
both vowel-harmony series, the d/t forms and any chain length are covered: plural,
possessive (all persons), case (accusative, dative, locative, ablative, genitive,
instrumental, equative) with the y, n and s buffer letters, -ki after a genitive or a
locative and what may follow it, and the -DIr copula. Softening (kitap, kitabı) and
derivations (-cı, -lık, -sız, -li) are not endings here.
"""

import re

TR_SUFFIXES_VERSION = 2

_A, _I, _D = "[ae]", "[iu]", "[dt]"
_PLURAL = f"l{_A}r"
_POSSESSIVE = f"(?:{_I}?m(?:{_I}z)?|{_I}?n(?:{_I}z)?|s?{_I})"
_GENITIVE_OR_LOCATIVE = f"(?:n?{_I}n|n?{_D}{_A})"
_CASE = f"(?:[yn]?{_I}|[yn]?{_A}|n?{_D}{_A}n?|n?{_I}n|y?l{_A}|n?c{_A})"
_COPULA = f"{_D}{_I}r(?:{_PLURAL})?"

TR_SUFFIX = re.compile(
    f"(?:{_PLURAL})?(?:{_POSSESSIVE})?"
    f"(?:{_GENITIVE_OR_LOCATIVE}ki(?:{_PLURAL})?(?:{_CASE})?|{_CASE})?"
    f"(?:{_COPULA})?"
)
