# Teams and gateway key controls

Teams belong to one organization. A membership names an existing organization
user and grants `member` or `team_admin` access to that team. An organization
role remains `owner`, `admin`, `member`, or `auditor`; a team administrator is
an organization member with a delegated membership, not another global role.

| Role | Gateway keys | Teams and memberships | Organization changes |
| --- | --- | --- | --- |
| Owner | All organization keys and policies | Create teams, set quotas, assign team administrators | Existing owner permissions |
| Admin | All organization keys and policies | Create teams, set quotas, assign team administrators | Existing admin permissions; cannot promote organization roles |
| Team administrator | Own keys and keys assigned to administered teams; edit those team keys' model policies | Add/remove ordinary members in administered teams | None |
| Member | Own keys; cannot loosen an existing key's model policy or reassign its access team | Read assigned teams | None |
| Auditor | Read key metadata; cannot issue, rotate, revoke, or use keys | Read organization teams and memberships | Read only |

Auditors can also list the model registry (`GET /api/v1/management/model-deployments`);
creating, changing and checking deployments stays with owners and admins.

Inviting a teammate needs a plan with team access (`team_rbac`). On a plan
without it, the invite answers 403 with a body that names the plans that have
the feature:

```json
{"detail": {"code": "PLAN_UPGRADE_REQUIRED", "feature": "team_rbac",
  "current_plan": "free", "eligible_plans": ["agency", "enterprise"],
  "message": "This feature needs one of the plans listed in eligible_plans."}}
```

Signing in creates a personal workspace. Accepting an invitation
(`POST /api/v1/management/team/invites/accept`) moves the user out of it:

- An unused personal workspace is archived. Unused means the invitee is its only
  user, it is on the free plan with no billing source or billing receipt, and it
  has no history: no request lifecycle, usage, quota, spend, audit intent or
  request log row (a `/v1/scan` with a key counts), and no compliance finding or
  activity collected by a connector. Its keys, provider secrets, deployments,
  budgets, teams, connectors, forward targets and privacy settings are deleted,
  so its keys stop authenticating, and the stored secrets (budget notification
  endpoints included) are deleted from the secret store after the change
  commits. Pending budget-alert and forward deliveries are cancelled, since
  their secrets are gone. The organization row stays with `archived_at` and
  `archived_reason: joined_organization`, its audit chain and undelivered audit
  appends stay, and the chain records `tenant.personal_workspace_archived`.
  Nobody can belong to it again, so it writes no new rows; the audit worker
  still anchors the archive day.
- A personal workspace with history is kept and the answer is 409
  "Your personal workspace has request history and cannot be archived; ask the
  inviting organization's owner to contact support."
- Any other workspace (more users, a paid plan, a billing source) answers 409
  "Leave or empty the current organization before accepting".

A workspace that never had a management action or a configuration row is
deleted instead of archived, as before.

Use **Workspace → Teams** to create a team, configure quotas, and assign
members. Use **Gateway → Keys** to assign a key's access team and model list.
Only organization owners/admins can move a key between teams. A member with
team memberships must select a team when creating a key. Removing membership
denies subsequent inference through that user's team keys; organization
owners/admins retain organization-wide authority.

## Service accounts

A service account lets a pipeline, a Terraform run or an agent call the
management API without a person's sign-in. It is an organization user of kind
`service` with the role `admin` or `auditor`, a synthetic address
`<id>@service-accounts.getshim.tech` that is never mailed, and a key
`sk-shim-svc-` followed by 64 hex characters, sent as `Authorization: Bearer`.

| Route | Who | What |
| --- | --- | --- |
| `POST /api/v1/management/service-accounts` | Owner | `{name, role, expires_in_days}` (1 to 365 days); answers 201 with the account and its key, shown once |
| `GET /api/v1/management/service-accounts` | Owner, admin (people only) | Name, role, key prefix, expiry, last use (to the minute), creator; never the key |
| `POST /api/v1/management/service-accounts/{id}/rotate` | Owner | A new key with the same expiry; the old key stops working at once |
| `DELETE /api/v1/management/service-accounts/{id}` | Owner | Deactivates the account, revokes its keys and its gateway keys |

- A service account follows its role's rules: an admin one can, for example,
  create gateway keys (owned by the service account), an auditor one is read-only
  like any auditor. It can never be owner, accept an invitation, manage service
  accounts or change members' roles, and `/team/members` does not list it.
- A revoked, expired, unknown or malformed key, or one of a deleted account,
  answers 401 `INVALID_API_KEY` without saying which. A gateway `sk-shim-` key
  is not accepted on management routes, and a service key is refused at the
  gateway routes.
- Every management action of a service account carries `actor_type: service`
  in the audit log; a person's carries `user_jwt`. Creating, rotating and
  deleting an account records `tenant.service_account_created`, `_rotated` and
  `_deleted`.

## Read scope

Organization-wide reads belong to owners, admins and auditors. Everyone, readers
included, reads their own usage with `GET /management/usage/mine?start=…&end=…`
(default the current UTC month to now, at most 31 days): totals, a daily UTC
series, and breakdowns by model and by API key (`api_key_id`, `name`,
`prefix`), with the billing cost semantics (`cost_usd` null and
`cost_complete: false` when a settlement had no price). A member reads
the requests of the keys they own and of the keys in teams they administer;
the filter is applied in the query, so totals, summaries, pages and the CSV
export cover only those keys. Other roles get 403 "Organization reader
required" on organization-wide reads.

| Read | Owner, admin, auditor | Member |
| --- | --- | --- |
| `/management/requests`, `/management/requests/export` | Whole organization | Own keys and administered teams' keys |
| `/management/overview`, `/management/billing/*`, `GET /management/cost/budgets` | Yes | 403 |
| `/compliance/overview`, `/compliance/audit/logs`, `/compliance/audit/bundle`, `POST /compliance/audit/verify`, `POST /compliance/reports/audit`, `POST /compliance/reports/kvkk` | Yes | 403 |
| Compliance connectors, findings, forward targets, oversight and oversight policies (`GET`) | Yes | 403 |
| `/management/model-deployments` (`GET`) | Yes | 403 |
| `/management/usage/mine` | Own keys and administered teams' keys | Own keys and administered teams' keys |
| `/team/members` (names and emails of the organization's users) | Yes | Team administrators only; other members 403 |
| `/auth/me`, `/subscription`, `/tier-info`, `GET /settings/pii`, `GET /settings/provider-keys`, `/teams`, `/api-keys` | Unchanged | Unchanged (keys and teams already scoped) |

## Attribution and migration

The existing `api_keys.team` value remains a billing label. The new `team_id`
is an explicit access and quota reference. They are intentionally independent.
The migration copies distinct existing labels into organization-owned team
names, preserving the original spelling. It does not assign memberships or
bind existing keys. Administrators explicitly assign access teams after
migration; historical request and billing labels are unchanged. Every request now
records its key's `team_id`; `GET /api/v1/management/billing/breakdown?group_by=team_id`
groups by it (`unassigned` for keys without a team and older requests), and each
row's `label` carries the team's current name (`null` for `unassigned` and for a
team that no longer exists), while `group_by=team` keeps grouping by the label.
Budgets follow the same split: scope `team_id` counts the requests of the
team's keys, labelled or not, and scope `team` matches the label
([alert on a budget](COOKBOOK.md#alert-on-a-budget)).

## Rotation and model policies

`POST /api/v1/management/api-keys/{id}/rotate` replaces the key's one-way verifier
in the same database row. The old secret stops authenticating when the
transaction commits. The response shows the new plaintext once. The key ID,
owner, team, expiry, tier, model policy and accumulated usage stay unchanged.
Already admitted requests can finish. Revoked or expired keys cannot rotate.

`allowed_models` contains exact, case-sensitive public model identifiers
(deployment aliases for registered models). `null` adds no key restriction;
`[]` denies every model. Workspace/provider policy still applies. Only an
organization administrator or the key's team administrator can edit this
policy after creation. Quota admission rechecks current key authorization and
model policy before reserving usage or calling a provider.

## Quotas

Team limits are optional nonnegative integers for daily requests, monthly
requests, and monthly tokens. `null` adds no team limit; zero denies admission.
Periods are UTC calendar days and months, beginning at 00:00 UTC.

Every request must fit both its existing per-key tier limit and its team's
shared allowance. Existing tier limits remain per-key; this change does not
add an organization-wide aggregate quota. Requests reserve one request and
estimated input plus maximum output tokens. Settlement replaces reserved token
usage with actual usage; refund releases both key and team reservations.

The existing PostgreSQL `quota_period_usage` table stores both scopes. One
usage-ledger event references all allocations, and conditional upserts fence
concurrent admissions. Redis is not a team quota ledger. Updating limits does
not reset consumed usage; lowering a limit below current usage denies further
admissions until usage is released or the next period starts.

Management changes append audit intent in their own committed transaction.
Quota and key policy changes include non-secret change facts. Identity-provider
memberships are synchronized through the same tenant boundary; local grants
remain authoritative and IdP-managed grants must be changed at the provider.

Run `uv run --locked python -m pytest -q ee/tests/tenants/test_teams.py` against
the disposable enterprise database to verify authorization, rotation,
membership synchronization and concurrent quota reservations.
