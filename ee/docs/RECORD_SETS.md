# Record sets

A record set lets a tenant rule catch two things no word list can: a customer of yours
named in a request (a **records** set built from your customer list), and a fragment of a
confidential document pasted into one (a **fingerprints** set). shim never receives the
list or the documents, only keyed hashes of them, and request content is never stored.

## What is hashed, and what never leaves your machine

`ee/scripts/hash_record_set.py` runs on your machine with the set's key. It reads the CSV
or the `.txt`/`.md` documents, and writes or uploads only:

- for a records set, every record as one 8-byte keyed hash per field (BLAKE2b with the
  set's 32-byte key over the field's normal form). A field is `tckn`, `vkn`, `iban`,
  `email`, `phone`, `digits` (with a length range), `token` (a customer number) or `name`
  (one to three letter words, so "Ayşe-Nur Yılmaz" and "Ayşe Nur Yılmaz" are the same name;
  a value with a digit is no name; case is folded and so are Turkish letters, the four I
  letters as `i` and ş ç ğ ö ü â î û as s c g o u a i u, so "AYSE YILMAZ", "Ayse Yilmaz"
  and "Ayşe Yılmaz" are one name, while "Aysel Yilmaz" or "Ayşe Yıldız" are not); a row
  without a primary value is dropped;
- for a fingerprints set, every document's winnowed fingerprints: 8-word shingles hashed
  with the key, keeping the smallest of every window of 4 (fingerprint version 1).

The tool prints counts only. Document labels (`doc-0001`, or the file names with
`--label-from-filename`) stay in a local `labels.json`; shim never sees them.

**A low-entropy field can be recovered from its hash by anyone who holds both the hashes
and the key.** A TCKN has 11 digits, so trying every one is cheap with the key. That is
why the key lives in the secret store, is shown once at creation, and is never returned
again. In the hosted cloud shim holds both the hashes and the key; record sets are your
reference data, not request content, so they are available there too.

## Create, upload, activate

1. `POST /api/v1/management/record-sets` (owner or admin, or `rules.write`) with
   `{"name", "kind", "label", "fields"}`. A records set has 2 to 6 fields, at least one
   primary; a primary is any kind but `name`, because the gateway finds it by its shape.
   The answer holds `hash_key` once: save it for the tool.
2. Run the tool with `--upload <base URL> --set <id>` and the admin bearer token in
   `SHIM_ADMIN_TOKEN` (or on standard input; never as an argument, which other users of
   the machine can read): it reads the set, refuses when the set's kind, or its fields'
   order, kinds, primary flags and lengths, differ from the ones hashed, then opens a
   revision, uploads the chunks and activates it. Or write the chunk files with `--out`
   and send them yourself:
   `POST .../record-sets/{id}/revisions` opens a revision, `PUT
   .../revisions/{n}/chunks/{index}` takes one chunk, `POST .../revisions/{n}/activate`
   checks the totals and activates it.
3. Add a `record_set` rule (`PUT /api/v1/management/rules`) in `monitor`, watch its
   `rule_matches`, then enforce it.

Activating keeps the revision before it, so activating that one again is a one-step
rollback; every other revision's chunks are deleted. Activating a revision that lacks any
record or document of the active one, byte for byte (fewer entries, an emptied field, or
as many entries but other ones), is recorded as a relaxation (`record_sets.<id>`).
Every activation records a [policy version](POLICY_DECISIONS.md#policy-versions-and-plans)
of the `record_sets` resource. While [four eyes](POLICY_DECISIONS.md#four-eyes) is on,
activating another revision of a set that an enforced rule uses answers 409
`CHANGE_REQUIRES_APPROVAL` (`record_sets.<id>.active_revision`): plan it instead
(`{"resource": "record_sets", "item": "<id>", "set": {"active_revision": <n>}}`) and
have a second administrator approve it. A set only `monitor` rules use, or none,
activates directly. A set a rule references
cannot be deleted (409 `RECORD_SET_IN_USE`; the rule set is locked while it is checked);
deleting removes the row,
its chunks and its key. `GET /record-sets` and `GET /record-sets/{id}` show metadata and
counts, never hashes or the key.

## Matching

A rule's `match` is `{"set_id", "min_fields": 2}` for a records set (1 to the set's field
count: how many of a record's fields, the primary included, must appear) or `{"set_id", "min_shared": 6}` for a
fingerprints set (2 to 200 shared fingerprints). In the privacy stage, for every string:

- records: values shaped like the set's primary fields are hashed and looked up; for each
  candidate record the other fields are looked for within 300 characters of the hit
  (names: every one to three letter words apart by spaces and at most one dash or
  apostrophe, in the folded form above, so a name typed without Turkish letters matches; phones also written with dots or brackets; a TCKN or VKN also grouped by
  spaces or hyphens; digits of any script, such as Arabic-Indic, count as the number they
  are). Fields are matched within one string: a record split across messages or content
  parts is not matched. At most 2,000 candidates per string; beyond, the match says
  `truncated: true`, and an enforced `mask` or `block` refuses the request with
  `RULE_BLOCKED`, because the records past the cap were never read;
- fingerprints: a string of 40 words or more is fingerprinted and compared.

The count is the distinct records or documents matched in the request. Enforced `mask`
(records sets only; fingerprints sets refuse it) replaces each matched field with the
set's label (`<RECORD_…>`), and a built-in type keeps its own (`TR_NATIONAL_ID`).
Enforced `block` refuses with `RULE_BLOCKED`; `warn` adds `RULE_WARN`. Nothing about a
match is recorded beyond the rule's count. A set that cannot be loaded is an evaluation
error: an enforced `mask` or `block` refuses with 503 `PRIVACY_STATE_UNAVAILABLE`
(`Retry-After: 5`), anything else records the error and continues.

## Limits

10 sets per organization; per set 250,000 records, or 2,000 documents and 2,000,000
fingerprints; chunks 0 to 499 of at most 10,000 records or 50 documents (20,000
fingerprints each), 4 MB a body. Each gateway process holds loaded sets of at most
128,000,000 bytes together and evicts the least recently used set; the first request
after an activation on each process waits for the set to load, once for all requests
waiting on it, in a short database session of its own (the sort runs after it closes).
Matching shares the request's 1-second rule search budget and stops when it runs out,
every pattern searched in linear time.
