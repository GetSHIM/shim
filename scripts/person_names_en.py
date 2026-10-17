"""Rebuild the sourced lists of `src/shim/privacy/data/en_person_names.json`.

    python scripts/person_names_en.py --sources <dir> --retrieved 2026-10-17

`<dir>` holds the archives as published: the SSA national baby names `names.zip`,
the Census 1990 `dist.female.first` and `dist.male.first`, and the Census 2010
surnames `names.zip` saved as `census2010-names.zip`. The script rewrites
`first_names` and `surnames` and their `source` entries and keeps the team-written
keys. It leaves out a sourced name that is a team-written following stopword, and a
first name the Turkish list holds that the Census 1990 lists do not: Turkish given
names belong to PERSON_NAME_TR.
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


def census_2010_surnames(archive: Path, ranks: int) -> list[str]:
    with zipfile.ZipFile(archive) as names:
        rows = csv.DictReader(
            io.TextIOWrapper(names.open("Names_2010Census.csv"), "ascii")
        )
        # Rank 0 is the "ALL OTHER NAMES" total.
        return [row["name"] for row in rows if 1 <= int(row["rank"]) <= ranks]


def build(
    data: dict, turkish: dict, sources: Path, min_births: int, retrieved: str
) -> dict:
    stopwords = {_fold(word) for word in data["following_stopwords"]}

    def kept(names: list[str]) -> list[str]:
        unique: dict[str, str] = {}
        for raw in names:
            name = _name(raw)
            if name.isalpha() and _fold(name) not in stopwords:
                unique.setdefault(_fold(name), name)
        return sorted(unique.values())

    births = ssa_births(sources / SSA[0])
    census_first = [
        name for file, _url in CENSUS_1990 for name in census_1990_first(sources / file)
    ]
    turkish_first = {
        _fold(name) for name in turkish["first_names"] + turkish["team_first_names"]
    } - {_fold(name) for name in census_first}
    first = [
        name
        for name, count in births.items()
        if count >= min_births and _fold(name) not in turkish_first
    ]
    surnames = census_2010_surnames(sources / CENSUS_2010[0], SURNAME_RANKS)
    census_1990 = "; ".join(
        _archive(sources, file, url, retrieved) for file, url in CENSUS_1990
    )
    return data | {
        "source": data["source"]
        | {
            "first_names": (
                f"US Social Security Administration national baby names, "
                f"{_archive(sources, *SSA, retrieved)}: every name with at least "
                f"{min_births} births over all years and both sexes, less the first "
                "names of tr_person_names.json that the Census 1990 lists lack; merged with "
                "the US Census 1990 "
                f"female and male first-name lists, {census_1990}, all entries; "
                "capitals written as names, one spelling per name ignoring case "
                "and accents, following stopwords left out; public domain (US "
                "federal works, 17 U.S.C. 105)"
            ),
            "surnames": (
                f"US Census 2010 surnames, {_archive(sources, *CENSUS_2010, retrieved)}"
                f", Names_2010Census.csv ranks 1 to {SURNAME_RANKS}; capitals written "
                "as names, following stopwords left out; public domain (US federal "
                "works, 17 U.S.C. 105)"
            ),
        },
        "first_names": kept(first + census_first),
        "surnames": kept(surnames),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sources", type=Path, required=True)
    parser.add_argument("--retrieved", required=True, help="YYYY-MM-DD")
    parser.add_argument("--min-births", type=int, default=1000)
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
