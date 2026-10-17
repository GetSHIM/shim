"""Rebuild the sourced lists of `src/shim/privacy/data/en_person_names.json`.

    python scripts/person_names_en.py --sources <dir> --retrieved 2026-10-17

`<dir>` holds the archives as published: the SSA national baby names `names.zip`,
the Census 1990 `dist.female.first` and `dist.male.first`, and the Census 2010
surnames `names.zip` saved as `census2010-names.zip`. The script rewrites
`first_names` and `surnames` and their `source` entries, and derives part of the
two ambiguous keys; it keeps the other team-written keys. Run on the archives whose
sha256 `source` records, with the defaults, it writes the committed file byte for byte.
Standard library only, so the shipped lists can be audited and rebuilt.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import unicodedata
from collections import Counter
from pathlib import Path
import zipfile

DATA = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "shim"
    / "privacy"
    / "data"
    / "en_person_names.json"
)
TURKISH = DATA.with_name("tr_person_names.json")
SSA = ("names.zip", "https://www.ssa.gov/oact/babynames/names.zip")
CENSUS_1990 = (
    (
        "dist.female.first",
        "https://www2.census.gov/topics/genealogy/1990surnames/dist.female.first",
    ),
    (
        "dist.male.first",
        "https://www2.census.gov/topics/genealogy/1990surnames/dist.male.first",
    ),
)
CENSUS_2010 = (
    "census2010-names.zip",
    "https://www2.census.gov/topics/genealogy/2010surnames/names.zip",
)
SURNAME_RANKS = 50_000
# A surname this frequent (34,949 people or more in 2010) is a name more often than a
# word after a given name: "Mark Brown", "Grace Young".
COMMON_SURNAME_RANKS = 1_000
# Dates, never names: "In July", "Thu Oct".
CALENDAR_WORDS = frozenset(
    {
        "january", "february", "march", "april", "may", "june", "july",
        "august", "september", "october", "november", "december",
        "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept",
        "oct", "nov", "dec",
        "monday", "tuesday", "wednesday", "thursday", "friday", "saturday",
        "sunday", "mon", "tue", "tues", "wed", "thu", "thur", "thurs", "fri",
        "sat", "sun",
    }
)  # fmt: skip


def _archive(directory: Path, name: str, url: str, retrieved: str) -> str:
    digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    return f"{url} (retrieved {retrieved}, sha256 {digest})"


def _fold(name: str) -> str:
    """Case and accents dropped, dotless i as i: "Ayşe" is SSA's "Ayse"."""
    decomposed = unicodedata.normalize("NFKD", name.replace("ı", "i"))
    return "".join(c for c in decomposed if not unicodedata.combining(c)).casefold()


def _name(raw: str) -> str:
    """Census lists are in capitals; a name is kept as it is usually written."""
    return raw if any(letter.islower() for letter in raw) else raw.capitalize()


def ssa_births(archive: Path) -> Counter[str]:
    """Births per name over every year and both sexes."""
    births: Counter[str] = Counter()
    with zipfile.ZipFile(archive) as names:
        for member in names.namelist():
            if member.startswith("yob") and member.endswith(".txt"):
                for row in csv.reader(io.TextIOWrapper(names.open(member), "ascii")):
                    births[row[0]] += int(row[2])
    return births


def census_1990_first(path: Path) -> list[str]:
    return [line.split()[0] for line in path.read_text("ascii").splitlines() if line]


def census_2010_surnames(archive: Path, ranks: int) -> dict[str, int]:
    """Each surname with its rank, ranks 1 to `ranks`."""
    with zipfile.ZipFile(archive) as names:
        rows = csv.DictReader(
            io.TextIOWrapper(names.open("Names_2010Census.csv"), "ascii")
        )
        # Rank 0 is the "ALL OTHER NAMES" total.
        return {
            row["name"]: int(row["rank"])
            for row in rows
            if 1 <= int(row["rank"]) <= ranks
        }


def build(
    data: dict, turkish: dict, sources: Path, min_births: int, retrieved: str
) -> dict:
    stopwords = {_fold(word) for word in data["following_stopwords"]}
    function_words = {_fold(word) for word in data["function_words"]}
    suffixes = {_fold(word) for word in data["name_suffixes"]}

    def kept(names: list[str], left_out: set[str]) -> list[str]:
        unique: dict[str, str] = {}
        for raw in names:
            name = _name(raw)
            if name.isalpha() and _fold(name) not in left_out:
                unique.setdefault(_fold(name), name)
        return sorted(unique.values())

    births = ssa_births(sources / SSA[0])
    census_first = [
        name for file, _url in CENSUS_1990 for name in census_1990_first(sources / file)
    ]
    ssa_first = [name for name, count in births.items() if count >= min_births]
    first = kept(ssa_first + census_first, stopwords | function_words)
    census = census_2010_surnames(sources / CENSUS_2010[0], SURNAME_RANKS)
    surnames = kept(list(census), stopwords | suffixes)
    rank = {_fold(name): place for name, place in census.items()}
    listed_surnames = {_fold(name) for name in surnames}
    # Turkish given names SSA counts but the Census 1990 lists lack: on Turkish text
    # they pair only with a listed surname.
    shared = {
        _fold(name) for name in turkish["first_names"] + turkish["team_first_names"]
    } & {_fold(name) for name in ssa_first} - {_fold(name) for name in census_first}
    listed_first = {_fold(name) for name in first + data["team_first_names"]}
    ambiguous_first = {
        _fold(name): name
        for name in data["ambiguous_first_names"]
        + [name for name in first if _fold(name) in CALENDAR_WORDS | shared]
        if _fold(name) in listed_first
    }
    # Surnames that are words, unless one is too frequent to be read as a word.
    words = CALENDAR_WORDS | function_words
    ambiguous_surnames = {
        _fold(name): name
        for name in data["ambiguous_surnames"]
        + [name for name in surnames if _fold(name) in words]
        if _fold(name) in listed_surnames
        and (_fold(name) in words or rank[_fold(name)] > COMMON_SURNAME_RANKS)
    }
    census_1990 = "; ".join(
        _archive(sources, file, url, retrieved) for file, url in CENSUS_1990
    )
    return data | {
        "source": data["source"]
        | {
            "first_names": (
                f"US Social Security Administration national baby names, "
                f"{_archive(sources, *SSA, retrieved)}: every name with at least "
                f"{min_births} births over all years and both sexes; merged with "
                "the US Census 1990 "
                f"female and male first-name lists, {census_1990}, all entries; "
                "capitals written as names, one spelling per name ignoring case "
                "and accents, following stopwords and function words left out; "
                "public domain (US federal works, 17 U.S.C. 105)"
            ),
            "surnames": (
                f"US Census 2010 surnames, {_archive(sources, *CENSUS_2010, retrieved)}"
                f", Names_2010Census.csv ranks 1 to {SURNAME_RANKS}; capitals written "
                "as names, following stopwords and name suffixes left out; public "
                "domain (US federal works, 17 U.S.C. 105)"
            ),
        },
        "first_names": first,
        "ambiguous_first_names": sorted(ambiguous_first.values()),
        "surnames": surnames,
        "ambiguous_surnames": sorted(ambiguous_surnames.values()),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--retrieved", required=True, help="YYYY-MM-DD")
    parser.add_argument("--min-births", type=int, default=2000)
    parser.add_argument("--data", type=Path, default=DATA)
    arguments = parser.parse_args()
    data = json.loads(arguments.data.read_text("utf-8"))
    turkish = json.loads(TURKISH.read_text("utf-8"))
    rebuilt = build(
        data, turkish, arguments.sources, arguments.min_births, arguments.retrieved
    )
    arguments.data.write_text(
        json.dumps(rebuilt, ensure_ascii=False, indent=1) + "\n", "utf-8"
    )


if __name__ == "__main__":
    main()
