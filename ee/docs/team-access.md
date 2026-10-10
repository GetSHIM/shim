# Teams and gateway key controls

Teams belong to one organization. A membership names an existing organization
user and grants `member` or `team_admin` access to that team. An organization
role is `owner`, `admin`, `member`, or `auditor`, or a member's
[custom role](#custom-roles); a team administrator is an organization member
with a delegated membership, not another global role.

## Permissions

Every management route asks for one permission. A built-in role holds a fixed
set; a role string the gateway does not know holds none, so it can neither
write nor own gateway keys.

| Permission | Allows | Owner | Admin | Member | Auditor |
| --- | --- | --- | --- | --- | --- |
| `settings.read` | Read the privacy and provider-key settings | x | x | x | x |
| `settings.write` | Change those settings and the organization name | x | x | | |
| `rules.read` | Read the rule set | x | x | | x |
| `rules.write` | Change the rule set | x | x | | |
| `deployments.read` | List the model registry | x | x | | x |
| `deployments.manage` | Create, change and health-check deployments | x | x | | |
| `providers.manage` | List, add, change, verify and delete provider credentials | x | x | | |
| `budgets.manage` | Create, change, delete and evaluate budgets | x | x | | |
| `teams.manage` | Create and change teams, grant or remove `team_admin` | x | x | | |
| `keys.own` | Create and hold one's own gateway keys | x | x | x | |
| `keys.manage` | Read and change every key, set `allowed_models` and `team_id` on keys without a team; owners and admins only | x | x | | |
| `members.read` | The member list with e-mail addresses | x | x | | x |
| `members.manage` | Invite, list and revoke invites, remove members | x | x | | |
| `roles.manage` | Change roles, invite or remove admins, custom roles, service accounts | x | | | |
| `usage.read` | Organization-wide requests, overview, billing, budgets and teams and keys | x | x | | x |
| `audit.read` | Compliance overview, audit log, bundle, verify, reports, reads of connectors, forward targets, oversight and readiness, and policy plans, versions and state | x | x | | x |
| `compliance.manage` | Connectors, forward targets, oversight, audit anchor, readiness declarations | x | x | | |
| `findings.read` | Read and export [findings](FINDINGS.md) | x | x | | x |
| `findings.manage` | Change a finding's status | x | x | | |
| `plans.create` | Create [policy plans](POLICY_DECISIONS.md#policy-versions-and-plans) and read them | x | x | | |
| `plans.apply` | Apply plans; with `plans.create`, restore a version | x | x | | |
| `plans.approve` | Approve or reject a pending plan | x | x | | |
| `requests.approve` | Decide request approvals | x | x | | |
| `content.read` | Open stored request content | x | x | | |
| `config.manage` | Signing keys and file mode | x | | | |

A permission without a route yet grants nothing. Team-scoped authority is not a
permission: a team administrator manages the keys and ordinary members of the
teams they administer, and everyone manages their own keys.

A write (any method but GET, HEAD and OPTIONS) by a user who holds only read
permissions answers 403 "Auditor access is read-only", except the four report
and verification POSTs readers may call (`/compliance/audit/verify` and
`/compliance/reports/audit`, `kvkk` and `readiness`). For a member with a
[custom role](#custom-roles) the rule covers organization writes, the routes
that ask for a permission; their own profile (`PUT /auth/me`), the teams they
administer, and their own keys, which follow `keys.own`, stay theirs. Only a
user whose role holds `keys.own` (owner, admin, member) can authenticate a
gateway key.
`GET /api/v1/management/auth/me` returns the caller's sorted `permissions` and
`custom_role`, so a dashboard can decide what to show from one call.

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
team memberships must select a team when creating a key, and can create a key
only on a team they belong to (403 "API-key owner is not a member of this team"
otherwise), the same rule the gateway applies to every request. Removing membership
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
| `GET /api/v1/management/service-accounts` | Owner | Name, role, key prefix, expiry, last use (to the minute), creator; never the key |
| `POST /api/v1/management/service-accounts/{id}/rotate` | Owner | A new key with the same expiry; the old key stops working at once. An expired key answers 409: create a new account |
| `DELETE /api/v1/management/service-accounts/{id}` | Owner | Deactivates the account, revokes its keys and its gateway keys |

- A service account follows its role's rules: an admin one can, for example,
  create gateway keys (owned by the service account), an auditor one is read-only
  like any auditor. It can never be owner, accept an invitation, manage service
  accounts, invite, remove members or change roles and team memberships (403),
  and `/team/members` does not list it.
- The gateway keys a service account creates belong to it and keep working after
  its own key expires. Deleting the account is what revokes them.
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
(default the UTC month of `end`, or of now, to `end`, at most 31 days): totals, a daily UTC
series (days and window follow when each request reconciled, like the totals),
and breakdowns by model and by API key (`api_key_id`, `name`,
`prefix`), with the billing cost semantics (`cost_usd` null and
`cost_complete: false` when a settlement had no price). A member reads
the requests of the keys they own and of the keys in teams they administer;
the filter is applied in the query, so totals, summaries, pages and the CSV
export cover only those keys. `api_key_id` narrows either read to one key and
never widens a member's scope: a key the member cannot see returns no rows. Other roles get 403 "Organization reader
required" on organization-wide reads.

| Read | Owner, admin, auditor | Member |
| --- | --- | --- |
| `/management/requests`, `/management/requests/export` | Whole organization | Own keys and administered teams' keys |
| `/management/overview`, `/management/billing/*`, `GET /management/cost/budgets` | Yes | 403 |
| `/compliance/overview`, `/compliance/audit/logs`, `/compliance/audit/bundle`, `POST /compliance/audit/verify`, `POST /compliance/reports/audit`, `POST /compliance/reports/kvkk` | Yes | 403 |
| Compliance connectors, findings, forward targets, oversight and oversight policies (`GET`) | Yes | 403 |
| `/management/model-deployments` (`GET`) | Yes | 403 |
| `/management/usage/mine` | Own keys and administered teams' keys | Own keys and administered teams' keys |
| `/team/members` (the organization's users, with `custom_role`) | Yes, with e-mail addresses | Team administrators only, with `email: null`; other members 403 |
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

## Custom roles

A custom role is a named set of permissions an owner gives to members, for
example a finance colleague who reads billing and nothing else. It needs a plan
with team access (`team_rbac`); every route below takes `roles.manage`, so only
owners call them.

| Route | What |
| --- | --- |
| `GET /api/v1/management/roles` | The organization's roles |
| `POST /api/v1/management/roles` | `{slug, name, permissions}`; answers 201 |
| `PUT /api/v1/management/roles/{role_id}` | Replaces slug, name and permissions |
| `DELETE /api/v1/management/roles/{role_id}` | 409 while a user holds it; removing a member frees the role |

- `slug` is 2 to 32 characters of `a-z`, `0-9` and `-`, starting with a letter,
  and not a built-in role name; `name` is up to 100 characters. An organization
  has at most 20 roles (409 beyond) and a slug once (409).
- `permissions` may hold any permission above except `roles.manage`,
  `config.manage`, `content.read`, `keys.manage`, `plans.approve` and
  `requests.approve`; any other string answers 422 naming it. A role stored
  with one of them before it was reserved does not grant it.
- `PATCH /api/v1/management/team/members/{member_id}` with `role: "member"` and
  `custom_role_id` gives a member the role; `custom_role_id: null` takes it away,
  and a role other than `member` clears it (422 when both are sent). The holder
  then has exactly the role's permissions instead of the member set.
- Only users whose permissions include `keys.own` may hold active gateway keys.
  Giving a role without it to a user with an active key, or removing it from a
  role whose holders have active keys, answers 409
  `{"code": "ROLE_HOLDERS_HAVE_KEYS", "users": <count>}`: revoke those keys first.
  An OIDC login that gives such a role revokes the user's active keys instead
  ([on-prem identity](ON_PREM_IDENTITY.md)).
- Changes record `tenant.custom_role_created`, `tenant.custom_role_updated`
  (before and after), `tenant.custom_role_deleted` and
  `tenant.member_custom_role_changed` (before and after slug).
- With `AUTH_MODE=oidc` the identity provider assigns custom roles through
  `OIDC_GROUP_CUSTOM_ROLE_MAP` ([on-prem identity](ON_PREM_IDENTITY.md)), and the
  PATCH answers 409 "Manage this role in the identity provider" for `custom_role_id`.
