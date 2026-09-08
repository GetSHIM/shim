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

Existing organization overview and member-directory visibility is preserved.
Team delegation limits mutation authority; it does not introduce a separate
tenant or hide existing organization aggregate dashboards.

Use **Workspace → Teams** to create a team, configure quotas, and assign
members. Use **Gateway → Keys** to assign a key's access team and model list.
Only organization owners/admins can move a key between teams. A member with
team memberships must select a team when creating a key. Removing membership
denies subsequent inference through that user's team keys; organization
owners/admins retain organization-wide authority.

## Attribution and migration

The existing `api_keys.team` value remains a billing label. The new `team_id`
is an explicit access and quota reference. They are intentionally independent.
The migration copies distinct existing labels into organization-owned team
names, preserving the original spelling. It does not assign memberships or
bind existing keys. Administrators explicitly assign access teams after
migration; historical request and billing labels are unchanged.

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
