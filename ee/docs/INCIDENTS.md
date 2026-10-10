# Incidents

An incident is the record a person opens when something went wrong: what
happened, who owns it, its status until it closes, the evidence it points at,
and the notification deadlines it starts. shim keeps the record and the clock
and reminds; it never decides whether something is a breach and never notifies
a regulator or a data subject itself.

## The record

`POST /api/v1/compliance/incidents` opens one with a `title` (up to 200
characters), an optional `description` (up to 2,000), a `severity_id` (OCSF: 1
informational, 2 low, 3 medium, 4 high, 5 critical), an optional
`owner_user_id` (a member of the organization), `occurred_at` and `aware_at`,
`is_suspected_breach`, `breach` and `links`. The caller is `opened_by`.

- `aware_at` is when the organization became aware; it defaults to now and
  cannot be in the future. `occurred_at`, when known, cannot be after it.
- `links` holds references only: `finding_ids` ([findings](FINDINGS.md)),
  `request_ids` and `audit_seqs` (audit chain sequence numbers), at most 100
  each, every one belonging to the organization. An id the organization does not
  have answers 422 naming the list. Nothing is copied from the linked rows.
- `breach` is the breach register, the organization's own text: `data_categories`
  (up to 20, each up to 100 characters), `approx_subjects` and `approx_records`
  (text, so "about 1,200" works), `likely_consequences`, `measures_taken`,
  `measures_planned` (up to 2,000 each), `contact_person` (up to 200),
  `subjects_informed` and `subjects_informed_how` (up to 500).

`GET /api/v1/compliance/incidents/{id}` also returns `evidence_summary`, computed
on every read from the linked rows: entity types with their KVKK category and
how many values were masked, monitored and blocked, the providers and models
the linked requests used, and the linked findings' rules and severities. It
suggests `data_categories`; shim never writes it into `breach`.

`PATCH` changes any of these fields; each link list sent replaces the stored
one.

## Status

| From | To |
| --- | --- |
| `new` | `in_progress` |
| `in_progress` | `on_hold`, `resolved` |
| `on_hold` | `in_progress` |
| `resolved` | `in_progress` (reopen), `closed` |

`POST /incidents/{id}/status` with `{status, note}` makes one move; any other
answers 409. `closed` is final: every write to a closed incident answers 409,
and a later event opens a new incident that names the old one in its
description.

## The clock

When `is_suspected_breach` becomes true, two notification rows appear:

| Regime | Deadline | Source |
| --- | --- | --- |
| `kvkk_board` | 72 hours from `aware_at` | KVKK Board decision 2019/10: "gecikmeksizin ve en geç 72 saat içinde"; information may be sent in stages |
| `kvkk_data_subjects` | none: "in the shortest reasonable time" | the same decision |
| `gdpr_authority` | 72 hours from `aware_at`, added by an admin | GDPR Art. 33, which exempts a breach unlikely to result in a risk |

These deadlines are fixed in code from the texts above, read from secondary
copies of the KVKK decision. **Confirm them with your counsel**; shim's clock is
a reminder, not legal advice. Turning the flag off keeps the rows and their
history. Changing `aware_at` moves the deadline of every row that has no
submission yet, and the audit row records the old and new time.

A row's state is derived on every read: `not_required` when an admin set
`required` false with a reason (for example GDPR's "unlikely to result in a
risk"), `submitted` once it has a submission, `overdue` when its deadline passed
without one, otherwise `open`.

- `PUT /incidents/{id}/notifications/{regime}` creates a row (the only way to
  add `gdpr_authority`) or sets `required` false with `not_required_reason`.
- `POST /incidents/{id}/notifications/{regime}/submissions` records what was
  sent, in stages: `submitted_at` (default now), `reference` (the form or case
  number, up to 200 characters), `fields_sent` (names of `breach` fields),
  `note` and, after the deadline, a mandatory `late_reason`. At most 20 per row.

## Reminders

On each pass the ai_act worker writes, for every required row with a deadline
and no submission, one `incident.deadline_approaching` intent when 24 hours or
less remain and one `incident.deadline_missed` intent once the deadline passed;
each stage is written once. The outbox worker sends them to every enabled
[forward target](COOKBOOK.md#send-tenant-alerts) with the incident id, title,
regime and deadline, never `breach` text. One organization's failure is logged
and the others still run.

## Export

`GET /api/v1/compliance/incidents/export` answers NDJSON, one OCSF 1.3.0
Incident Finding (`class_uid` 2005) per incident: `activity_id` 1 for `new`, 2
for `in_progress` and `on_hold`, 3 for `resolved` and `closed`; `status_id` 1 to
5 in the order of the status table with its caption; `severity_id`; `time`
(the last change); `finding_info_list` (the linked findings, or the incident
itself); `desc`; `start_time` (`occurred_at`); `is_suspected_breach`;
`assignee`; and under `unmapped` the notification rows (deadline, state,
submission count and references) and the linked request ids and audit
sequences. `contact_person` and the free-text breach fields are never exported.

## Access

`incidents.read` (owner, admin, auditor) lists, reads and exports;
`incidents.manage` (owner, admin) writes. Every write is audited by field name:
`tenant.incident_opened`, `tenant.incident_updated`,
`tenant.incident_status_changed` and `tenant.incident_notification_recorded`.
The audit row never carries `breach` text.

## What shim does not do

- Open incidents by itself from findings or alerts.
- File with the KVKK portal or any other regulator, or tell data subjects.
- Decide whether an event is a breach or whether a notification is required.
- Store request or answer content in an incident.
- Track EU AI Act serious-incident deadlines, which run on different clocks.
