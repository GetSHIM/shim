"""Generate the labelled PII corpus and the evasion corpus, deterministically.

Every identifier is synthetic and checksum-valid (TCKN, VKN, TR IBAN, Luhn cards,
phonenumbers-valid phones). Hard negatives look like identifiers but are not: order
and invoice numbers that fail the TCKN and VKN checksums, EAN barcodes, dates, prices,
timestamps, four-part version numbers and commit hashes. Spans are exact character
offsets into `text`.

    python -m scripts.bench.pii_corpus --out scripts/bench/results/corpus

writes corpus.jsonl and evasion.jsonl and prints their SHA-256, which must match the
published one for the same --seed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import string
import uuid
from pathlib import Path

import phonenumbers

SEED = 20261015

# Held-out names. None of them appears in the S41 lists that tuned shim's Turkish
# name detector (checked when these lists were written). Most Turkish ones are common
# names and do appear in shim's shipped dictionary (derived from Faker's tr_TR data);
# the English ones do not, and shim has no English name detector.
TR_FIRST = (
    "Abdurrahman Adem Alparslan Arda Atakan Aykut Bahadır Bedirhan Berat Bora Cafer "
    "Celal Cihan Davut Ekrem Enver Erol Ertan Fikret Fuat Hakkı Hamdi Haluk İlhan "
    "İsmet Kâzım Mazhar Muammer Nail Necmettin Nevzat Oktay Rasim Remzi Sabri Sadık "
    "Şenol Tahsin Talat Turgut Vedat Yaşar Zeki Zülfikar Cemil Tayfun Uğur Hilmi Lütfi "
    "Necdet Ayten Berna Betül Canan Emel Feride Figen Gönül Gülay Gülten Hale Jale Mine "
    "Müjgan Nalan Nazan Nebahat Nurten Oya Saadet Sevinç Şükran Türkan Ülkü Vildan "
    "Yeter Zuhal Aysel Asuman Birsen Füsun Gülizar İlknur Nuray Semra"
).split()
TR_LAST = (
    "Acar Akbulut Akın Altıntaş Avcı Aydemir Başer Bektaş Bingöl Boz Coşkun Dalkılıç "
    "Durmaz Eker Erbaş Erdoğdu Eroğlu Güneri Gündüz Güven Işıklar Kalkan Karabulut "
    "Kavak Keskin Kocabaş Kahraman Kurtuluş Oral Oruç Özbek Özcan Özgür Saygın Soylu "
    "Şen Taşdemir Toprak Türkmen Uçak Ünlü Yaman Yazar Yeşil Yüksel Zengin Akkaya Duran "
    "Ekşi Gürbüz İnce"
).split()
EN_FIRST = (
    "Abigail Adrian Alistair Bethany Brandon Caleb Chloe Colin Daphne Declan Eleanor "
    "Elliot Felicity Gareth Georgia Graham Harriet Imogen Jasper Jocelyn Kieran Lydia "
    "Malcolm Miriam Nathaniel Olivia Patrick Penelope Quentin Rebecca Rupert Samantha "
    "Theodore Ursula Vincent Wendy Xavier Yvonne Zachary Margaret Douglas Heather "
    "Trevor Gwendolyn"
).split()
EN_LAST = (
    "Abernathy Blackwood Callahan Davenport Ellison Fairbanks Gallagher Hargreaves "
    "Ingram Jennings Kowalski Lancaster McAllister Northcott O'Connell Pemberton "
    "Quinlan Rutherford Sinclair Thornton Underwood Vaughan Whitaker Yardley "
    "Zimmerman Brennan Castillo Donnelly Fitzgerald Hawthorne"
).split()
DOMAINS = (
    "example.com",
    "example.org",
    "ornek.com.tr",
    "posta.example.net",
    "mail.example.co.uk",
)
ASCII_FOLD = str.maketrans("çğıöşüâîûÇĞİÖŞÜÂÎÛ'", "cgiosuaiuCGIOSUAIU-")
MONTHS = "January February March April May June July August September October November December".split()

TEMPLATES = (
    # Support chat, Turkish.
    "[09:41] Müşteri: Merhaba, ben {person_tr}. Dün {price} tutarında ödeme yaptım ama "
    "sipariş görünmüyor. Sipariş no {order_no}.\n[09:42] Temsilci: Kimlik doğrulaması "
    "için TC kimlik numaranızı alabilir miyim?\n[09:43] Müşteri: {tckn}, telefonum "
    "{phone_tr}.\n[09:44] Temsilci: Teşekkürler, kaydınızı {date} tarihli faturayla "
    "eşleştirdim.",
    # Bank email, Turkish.
    "Konu: Havale talimatı\n\nSayın {person_tr},\n\n{date} tarihli talimatınız "
    "doğrultusunda {price} tutarındaki ödeme {iban} numaralı hesaba gönderilecektir. "
    "Vergi kimlik numaranız ({vkn}) ile fatura bilgileriniz eşleşmektedir. Sorularınız "
    "için {email} adresine yazabilirsiniz.\n\nFatura no: {invoice_no}",
    # Bank email, English.
    "Subject: Card dispute {case_no}\n\nDear {person_en},\n\nWe received your dispute "
    "for the transaction of {price_usd} on {date_en}. The card {card} has been "
    "temporarily blocked. Please call us at {phone_intl} or reply to {email}.\n\n"
    "Kind regards,\nCard Services",
    # Application log.
    "{ts_iso} INFO  auth     login ok user={email} ip={ip} session={uuid}\n"
    "{ts_iso2} WARN  payment  retry order_id={order_no} amount={price_plain} "
    "latency_ms=412\n{ts_iso3} ERROR payment  card declined pan={card} "
    "customer_tckn={tckn}\n{ts_iso4} DEBUG build    version={version} commit={sha}",
    # Environment file.
    "# deploy/.env.production\nAWS_ACCESS_KEY_ID={aws_key}\nAWS_REGION=eu-central-1\n"
    "GITHUB_TOKEN={gh_token}\nSENTRY_RELEASE={sha}\nAPP_BUILD={timestamp_ms}\n",
    # Python snippet.
    'import requests\n\nheaders = {{"Authorization": "Bearer {jwt}"}}\n'
    'resp = requests.get("https://api.example.com/v2/orders/{order_no}", '
    "headers=headers, timeout=30)\n# TODO: ask {person_en} why this returns 403 since "
    "build {version}\n",
    # Support ticket with a curl command.
    "Hi team, our integration fails. Request:\ncurl -H 'Authorization: token "
    "{gh_token}' https://api.github.com/repos/acme/billing/issues\nOur egress IP is "
    "{ip}. Contact me at {email} or {phone_intl}.\n— {person_en}",
    # Mixed Turkish and English incident chat.
    "@here prod incident: {person_tr} reported that customer {person_tr2} ({email}) "
    "got charged twice, {price}. Card: {card}. Rollback'i 14:05 gibi yaptık, build "
    "{version}. Ticket #{ticket}.",
    # HR note, English.
    "HR note — {date_en}\nEmployee: {person_en}\nPersonal phone: {phone_intl}\n"
    "Payroll IBAN: {iban}\nTurkish ID (for the Istanbul office contract): {tckn}\n"
    "Start date {date_en2}, salary band B3.",
    # CRM export.
    "ad_soyad,tckn,telefon,eposta,il,son_siparis\n{person_tr},{tckn},{phone_tr},"
    "{email},İstanbul,{order_no}\n{person_tr2},{tckn2},{phone_tr2},{email2},Ankara,"
    "{order_no2}",
    # Tool result JSON.
    '{{"customer": {{"name": "{person_tr}", "tax_id": "{vkn}", "iban": "{iban}", '
    '"phone": "{phone_tr}"}}, "order": {{"id": "{order_no}", "total": '
    '"{price_plain}", "created_at": "{ts_iso}"}}}}',
    # Complaint, Turkish.
    "Şikayet: {date} tarihinde verdiğim {order_no} numaralı siparişim hâlâ teslim "
    "edilmedi. Kargo takip numarası {tracking}. Fatura no {invoice_no}. Adım "
    "{person_tr}, kimlik no {tckn}. Bana {phone_tr} numarasından ulaşabilirsiniz.",
    # Release notes, English: mostly hard negatives.
    "Release notes {version}: fixed rounding for totals like {price_usd}; invoices "
    "dated {date_en} now export correctly. Reference build {timestamp_ms}. Thanks to "
    "{person_en} for the report.",
    # Campaign text, Turkish: hard negatives only.
    "Kampanya: {date} ile {date2} arasında {price} üzeri siparişlerde kargo bedava. "
    "Sipariş numaranız {order_no}, fatura numaranız {invoice_no}, kargo takip no "
    "{tracking}. Ürün barkodu {ean}.",
    # Secrets pasted into a chat, English.
    "can you debug this? jwt={jwt} and my aws key is {aws_key}. ignore the hash "
    "{sha}, that's the commit.",
    # Database error.
    "psycopg.errors.UniqueViolation: duplicate key value violates unique constraint "
    '"customers_tckn_key"\nDETAIL:  Key (tckn)=({tckn}) already exists.\nCONTEXT:  '
    "INSERT INTO customers (full_name, email, vkn) VALUES ('{person_tr}', '{email}', "
    "'{vkn}')",
)


def digits(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.digits) for _ in range(n))


def tckn_check(nine: str) -> str:
    d = [int(c) for c in nine]
    tenth = ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10
    return f"{tenth}{(sum(d) + tenth) % 10}"


def tckn(rng: random.Random) -> str:
    nine = rng.choice("123456789") + digits(rng, 8)
    return nine + tckn_check(nine)


def vkn_check(nine: str) -> str:
    total = 0
    for i, c in enumerate(nine):
        value = (int(c) + 9 - i) % 10
        if value:
            value = (value * 2 ** (9 - i)) % 9 or 9
        total += value
    return str((10 - total % 10) % 10)


def vkn(rng: random.Random) -> str:
    nine = digits(rng, 9)
    return nine + vkn_check(nine)


def luhn_ok(number: str) -> bool:
    total = 0
    for i, c in enumerate(reversed(number)):
        d = int(c) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def luhn_complete(prefix: str, length: int, rng: random.Random) -> str:
    body = prefix + digits(rng, length - len(prefix) - 1)
    return next(body + c for c in string.digits if luhn_ok(body + c))


def grouped(value: str, sizes: tuple[int, ...], separator: str) -> str:
    parts, at = [], 0
    for size in sizes:
        parts.append(value[at : at + size])
        at += size
    return separator.join(part for part in parts if part)


def card(rng: random.Random) -> str:
    prefix, length = rng.choice(
        (("4", 16), ("51", 16), ("55", 16), ("2221", 16), ("37", 15), ("9792", 16))
    )
    number = luhn_complete(prefix, length, rng)
    sizes = (4, 6, 5) if length == 15 else (4, 4, 4, 4)
    return grouped(number, sizes, rng.choice((" ", "-", "")))


def iban(rng: random.Random) -> str:
    bban = digits(rng, 5) + "0" + digits(rng, 16)
    check = 98 - int(bban + "292700") % 97  # "TR00" with T=29, R=27.
    value = f"TR{check:02d}{bban}"
    return grouped(value, (4,) * 6 + (2,), " ") if rng.random() < 0.7 else value


def phone(rng: random.Random, region: str) -> str:
    while True:
        if region == "TR":
            raw = rng.choice(("05", "02")) + digits(rng, 9)
        else:
            raw = rng.choice(("+1202555", "+4420794", "+493090")) + digits(rng, 4)
        number = phonenumbers.parse(raw, region if region == "TR" else None)
        if phonenumbers.is_valid_number(number):
            break
    style = rng.choice(
        (
            phonenumbers.PhoneNumberFormat.INTERNATIONAL,
            phonenumbers.PhoneNumberFormat.E164,
            phonenumbers.PhoneNumberFormat.NATIONAL,
        )
    )
    return phonenumbers.format_number(number, style)


def person(rng: random.Random, language: str) -> str:
    first, last = (TR_FIRST, TR_LAST) if language == "tr" else (EN_FIRST, EN_LAST)
    return f"{rng.choice(first)} {rng.choice(last)}"


def email(rng: random.Random) -> str:
    first, last = person(rng, rng.choice(("tr", "en"))).translate(ASCII_FOLD).split()
    local = rng.choice(
        (f"{first}.{last}", f"{first[0]}{last}", f"{first}{digits(rng, 2)}")
    )
    return f"{local.lower()}@{rng.choice(DOMAINS)}"


def ip(rng: random.Random) -> str:
    net = rng.choice(
        (
            "192.0.2",
            "198.51.100",
            "203.0.113",
            f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}",
        )
    )
    if rng.random() < 0.15:
        return f"2001:db8:{rng.randint(1, 0xFFFF):x}::{rng.randint(1, 0xFFFF):x}"
    return f"{net}.{rng.randint(1, 254)}"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt(rng: random.Random) -> str:
    claims = {
        "sub": digits(rng, 8),
        "role": "agent",
        "iat": 1_791_000_000 + rng.randint(0, 9_999_999),
    }
    head = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url(json.dumps(claims).encode())
    return f"{head}.{body}.{b64url(rng.randbytes(32))}"


def token(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def github_token(rng: random.Random) -> str:
    alnum = string.ascii_letters + string.digits
    if rng.random() < 0.5:  # Fine-grained personal access token.
        return f"github_pat_{token(rng, alnum, 22)}_{token(rng, alnum, 59)}"
    return f"{rng.choice(('ghp', 'gho', 'ghs'))}_{token(rng, alnum, 36)}"


def failing(rng: random.Random, n: int, valid) -> str:
    while True:
        value = rng.choice("123456789") + digits(rng, n - 1)
        if not valid(value):
            return value


def ean13(rng: random.Random) -> str:
    body = "869" + digits(rng, 9)  # GS1 Turkey prefix.
    check = (
        10 - sum(int(c) * (3 if i % 2 else 1) for i, c in enumerate(body)) % 10
    ) % 10
    return f"{body}{check}"


def date_tr(rng: random.Random) -> str:
    return f"{rng.randint(1, 28):02d}.{rng.randint(1, 12):02d}.2026"


def date_en(rng: random.Random) -> str:
    day, month = rng.randint(1, 28), rng.randint(1, 12)
    return rng.choice(
        (f"{MONTHS[month - 1]} {day}, 2026", f"2026-{month:02d}-{day:02d}")
    )


def ts_iso(rng: random.Random) -> str:
    return f"2026-10-{rng.randint(1, 14):02d}T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}.{digits(rng, 3)}Z"


# slot -> (label, generator). A label starting with NEG_ marks a hard negative.
SLOTS = {
    "tckn": ("TCKN", tckn),
    "vkn": ("VKN", vkn),
    "iban": ("IBAN", iban),
    "card": ("CARD", card),
    "phone_tr": ("PHONE", lambda rng: phone(rng, "TR")),
    "phone_intl": ("PHONE", lambda rng: phone(rng, "INTL")),
    "email": ("EMAIL", email),
    "ip": ("IP", ip),
    "aws_key": (
        "AWS_KEY",
        lambda rng: "AKIA" + token(rng, string.ascii_uppercase + "234567", 16),
    ),
    "gh_token": ("GITHUB_TOKEN", github_token),
    "jwt": ("JWT", jwt),
    "person_tr": ("PERSON", lambda rng: person(rng, "tr")),
    "person_en": ("PERSON", lambda rng: person(rng, "en")),
    "order_no": (
        "NEG_ORDER_NO",
        lambda rng: failing(rng, 11, lambda v: tckn_check(v[:9]) == v[9:]),
    ),
    "invoice_no": (
        "NEG_INVOICE_NO",
        lambda rng: failing(rng, 10, lambda v: vkn_check(v[:9]) == v[9]),
    ),
    "tracking": (
        "NEG_TRACKING_NO",
        lambda rng: rng.choice("123456789") + digits(rng, 11),
    ),
    "ean": ("NEG_BARCODE", ean13),
    "date": ("NEG_DATE", date_tr),
    "date_en": ("NEG_DATE", date_en),
    "price": (
        "NEG_PRICE",
        lambda rng: f"{rng.randint(1, 9)}.{digits(rng, 3)},{digits(rng, 2)} TL",
    ),
    "price_usd": (
        "NEG_PRICE",
        lambda rng: f"${rng.randint(1, 9)},{digits(rng, 3)}.{digits(rng, 2)}",
    ),
    "price_plain": (
        "NEG_PRICE",
        lambda rng: f"{rng.randint(10, 9999)}.{digits(rng, 2)}",
    ),
    "ts_iso": ("NEG_TIMESTAMP", ts_iso),
    "timestamp_ms": (
        "NEG_TIMESTAMP",
        lambda rng: str(1_791_000_000_000 + rng.randint(0, 9_999_999_999)),
    ),
    "version": (
        "NEG_VERSION",
        lambda rng: (
            f"{rng.randint(1, 9)}.{rng.randint(0, 30)}.{rng.randint(0, 9)}.{rng.randint(100, 999)}"
        ),
    ),
    "sha": ("NEG_COMMIT", lambda rng: rng.randbytes(20).hex()),
    "uuid": (
        "NEG_UUID",
        lambda rng: str(uuid.UUID(bytes=rng.randbytes(16), version=4)),
    ),
    "ticket": ("NEG_TICKET", lambda rng: digits(rng, 6)),
    "case_no": ("NEG_CASE_NO", lambda rng: f"CASE-2026-{digits(rng, 6)}"),
}


def render(template: str, rng: random.Random) -> dict:
    text, spans = [], []
    at = 0
    for literal, field, _, _ in string.Formatter().parse(template):
        text.append(literal)
        at += len(literal)
        if field is None:
            continue
        label, make = SLOTS[field.rstrip("0123456789")]
        value = make(rng)
        span = {"start": at, "end": at + len(value), "label": label}
        if label == "PERSON":
            span["lang"] = "tr" if field.startswith("person_tr") else "en"
        spans.append(span)
        text.append(value)
        at += len(value)
    return {"text": "".join(text), "spans": spans}


# Disguises: what an attacker or a messy client does to an identifier.
def _digit_map(zero: int):
    return lambda v: "".join(chr(zero + int(c)) if c.isdigit() else c for c in v)


def _fullwidth(v: str) -> str:
    return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in v)


def _between(mark: str):
    return lambda v: mark.join(v)


def _after_each(mark: str):
    return lambda v: "".join(c + mark if c.isalnum() else c for c in v)


def _mixed_case(v: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(v))


def _hyphen_groups(v: str) -> str:
    v = v.replace(" ", "")
    return "-".join(v[i : i + 3] for i in range(0, len(v), 3))


def _line_break(v: str) -> str:
    local, _, domain = v.partition("@")
    return f"{local}@\n{domain}"


DISGUISES = {
    "plain": (lambda v: v, ("TCKN", "IBAN", "CARD", "PHONE", "EMAIL")),
    "arabic_indic_digits": (_digit_map(0x0660), ("TCKN", "IBAN", "CARD", "PHONE")),
    "extended_arabic_indic_digits": (
        _digit_map(0x06F0),
        ("TCKN", "IBAN", "CARD", "PHONE"),
    ),
    "devanagari_digits": (_digit_map(0x0966), ("TCKN", "IBAN", "CARD", "PHONE")),
    "fullwidth": (_fullwidth, ("TCKN", "IBAN", "CARD", "PHONE", "EMAIL")),
    "combining_mark_per_char": (
        _after_each("́"),
        ("TCKN", "IBAN", "CARD", "PHONE", "EMAIL"),
    ),
    "zero_width_joiner": (_between("‍"), ("TCKN", "IBAN", "CARD", "PHONE", "EMAIL")),
    "space_per_char": (
        lambda v: " ".join(v.replace(" ", "")),
        ("TCKN", "IBAN", "CARD", "PHONE"),
    ),
    "hyphen_groups": (_hyphen_groups, ("TCKN", "IBAN", "CARD", "PHONE")),
    "bidi_override_wrap": (
        lambda v: f"‮{v}‬",
        ("TCKN", "IBAN", "CARD", "PHONE", "EMAIL"),
    ),
    "bidi_override_reversed": (
        lambda v: f"‮{v[::-1]}‬",
        ("TCKN", "IBAN", "CARD", "PHONE", "EMAIL"),
    ),
    "mixed_case": (_mixed_case, ("EMAIL",)),
    "line_break": (_line_break, ("EMAIL",)),
}
CARRIERS = {
    "TCKN": (
        "Müşterinin TC kimlik numarası {}, lütfen kaydı güncelleyin.",
        "The customer's Turkish ID is {}, please update the record.",
    ),
    "IBAN": (
        "Ödemeyi şu IBAN'a yapın: {} teşekkürler.",
        "Please wire the refund to IBAN {} today.",
    ),
    "CARD": (
        "Kart numaram {} ama ödeme geçmiyor.",
        "My card number is {} and the payment keeps failing.",
    ),
    "PHONE": (
        "Beni {} numarasından arayabilirsiniz.",
        "You can call me on {} after lunch.",
    ),
    "EMAIL": ("Yanıtı {} adresine gönderin.", "Send the answer to {} please."),
}
EVASION_VALUES = {
    "TCKN": tckn,
    "IBAN": lambda rng: iban(rng).replace(" ", ""),
    "CARD": lambda rng: luhn_complete(rng.choice(("4", "51")), 16, rng),
    "PHONE": lambda rng: phonenumbers.format_number(
        phonenumbers.parse(phone(rng, "TR"), "TR"), phonenumbers.PhoneNumberFormat.E164
    ),
    "EMAIL": email,
}


def evasion_cases(rng: random.Random, per_cell: int) -> list[dict]:
    cases = []
    for disguise, (apply, types) in DISGUISES.items():
        for label in types:
            for n in range(per_cell):
                value = EVASION_VALUES[label](rng)
                shown = apply(value)
                prefix, suffix = CARRIERS[label][n % 2].split("{}")
                cases.append(
                    {
                        "id": f"ev-{disguise}-{label.lower()}-{n:03d}",
                        "disguise": disguise,
                        "text": f"{prefix}{shown}{suffix}",
                        "spans": [
                            {
                                "start": len(prefix),
                                "end": len(prefix) + len(shown),
                                "label": label,
                                "value": value,
                            }
                        ],
                    }
                )
    return cases


def write(path: Path, rows: list[dict]) -> str:
    data = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows
    )
    path.write_text(data, encoding="utf-8")
    return hashlib.sha256(data.encode()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="directory for corpus.jsonl and evasion.jsonl",
    )
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument(
        "--per-template", type=int, default=30, help="cases per template"
    )
    parser.add_argument(
        "--per-cell", type=int, default=20, help="evasion cases per disguise and type"
    )
    args = parser.parse_args()
    rng = random.Random(args.seed)
    corpus = [
        {"id": f"c{t:02d}-{n:03d}", "template": t, **render(template, rng)}
        for t, template in enumerate(TEMPLATES)
        for n in range(args.per_template)
    ]
    evasion = evasion_cases(rng, args.per_cell)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, rows in (("corpus.jsonl", corpus), ("evasion.jsonl", evasion)):
        print(f"{name}: {len(rows)} cases, sha256 {write(args.out / name, rows)}")


if __name__ == "__main__":
    main()
