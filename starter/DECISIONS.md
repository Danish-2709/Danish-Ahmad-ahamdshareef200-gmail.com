# DECISIONS

These are the implementation decisions where I had a plausible alternative and had
to choose based on observed behaviour, tests, or the database rather than simply
transcribing the documents.

---

### 1. Permission resolution is database-driven, not hard-coded from the documented roles

**What I chose:** Resolve roles, permissions, grants, and permission patterns from the
database at runtime.

**Why:** The personalized fixture contains a role and permission that are not part of
the documented matrix. My Phase 2 baseline also showed a device-scoped
`device:reboot` allow and deny on two different devices. The README explicitly warns
that the database is the model and that hard-coding the documented matrix will fail
against the personalized fixture. `node scripts/check-permissions.js` finished at
35/35 after the resolver was made database-driven.

**What I rejected:** Hard-coding the five documented roles and their permission
lists. That would have been simpler, but it would make the implementation depend on
the readable fixture instead of the actual database contents.

**What would change my mind:** A requirement that the permission catalogue be
immutable application configuration rather than database reference data.

---

### 2. Explicit deny wins during permission resolution

**What I chose:** Evaluate the applicable role baseline and grants so that an explicit
deny produces `explicit_deny` rather than allowing another applicable allow to
override it.

**Why:** The personalized fixture deliberately places an allow and a deny for the
same permission on different devices, and the permission suite exercises those
different outcomes. During implementation I initially had incorrect resolution
details; the test output exposed the expected effect/reason contract. I kept the
precedence centralized in `server/permissions.js`, which is also the repository's
single permission decision point.

**What I rejected:** Treating the most recently-created grant as authoritative, or
letting an allow override a deny. Neither gives a stable interpretation of
conflicting grants.

**What would change my mind:** A documented rule or test demonstrating that an
applicable allow is intentionally able to override an explicit deny at the same
scope.

---

### 3. Session authorization checks the start permission separately from the requested mode

**What I chose:** A session request must satisfy `session:start` and the permission
for the requested mode/device independently.

**Why:** The API suite produced a case where a viewer could view `lab-mac-01` through
a grant but could not start a session. The test specifically distinguishes the
missing `session:start` reason from the mode/control failure. The final API suite
passes both cases.

**What I rejected:** Treating `device:view`, `device:control`, or another mode
permission as sufficient to start any session. That collapses two distinct
authorization questions and loses the reason the API is expected to report.

**What would change my mind:** A contract explicitly defining session-start as an
implicit consequence of every individual mode permission.

---

### 4. Permission changes invalidate fresh authorization without terminating grandfathered sessions

**What I chose:** Increment the membership permission version when authorization
changes, reject an old access token as `TOKEN_STALE`, but leave an already-running
session alive.

**Why:** The API suite demonstrated the distinction directly: after Sam was
demoted, his existing session survived, while a new session was blocked and his
old token became stale. The README also describes sessions as grandfathered and
distinguishes permission changes from suspension and membership removal.

**What I rejected:** Ending every active session whenever a role or grant changes.
That would incorrectly turn a permission change into a session lifecycle event.

**What would change my mind:** A security requirement stating that every permission
change must immediately terminate all active sessions.

---

### 5. Suspension is treated differently from an ordinary permission change

**What I chose:** Suspending a membership increments its permission version and
actively ends that user's existing sessions with `user_suspended`.

**Why:** The API suite explicitly checks this distinction. A permission change
preserves an existing session, while suspension ends it. The test passed both the
ended state and the `user_suspended` reason, and reinstatement restored access.

**What I rejected:** Applying the grandfathering rule to suspension as well. That
would allow an account whose membership is suspended to keep an active session.

**What would change my mind:** A tenancy model where suspension only affects future
authorization and explicitly permits existing sessions to continue until TTL.

---

### 6. Organization ownership is constrained by last-owner protection

**What I chose:** The creator of a new organization becomes its owner; an owner
cannot leave if they are the last active owner, while a non-last owner can be
demoted or leave.

**Why:** The API suite directly verifies all three boundaries: organization
creation makes the creator the sole owner, the sole owner receives `LAST_OWNER`,
and demoting a non-last owner succeeds. It also verifies that an admin cannot
confer the owner role.

**What I rejected:** Treating all owners identically and allowing the last owner to
leave, or allowing an administrator to assign ownership simply because the admin
can modify other roles.

**What would change my mind:** A lifecycle requirement that allows organizations
without an owner or gives another mechanism for ownership transfer.

---

### 7. Invite tokens are stored hashed, while the raw token is returned only at creation

**What I chose:** Generate a random invite token, store only its hash in the
database, return the raw token once when the invite is created, and use the hash
for public preview and acceptance.

**Why:** The invite API contract tests single-use behaviour: creation returns the
token, public preview succeeds with that token, acceptance succeeds once, reuse
returns 409, and the resulting user can log in. The implementation hashes the
token before inserting it and hashes the presented token when looking it up.

**What I rejected:** Storing the raw invite token in the `invites` table. That
would make the database itself a reusable source of invitation credentials.

**What would change my mind:** A requirement to recover the original invitation
credential from the database after creation.

---

### 8. The invite creation response follows the actual API contract, including the top-level inviteToken

**What I chose:** Return the raw invitation credential as `inviteToken` at the
top level of the creation response, while keeping the non-secret invite metadata
inside `invite`.

**Why:** My first implementation returned the raw value as `invite.token`.
`check-api.js` explicitly reads `inv.body.inviteToken`, so the first run reported
`raw token returned once -> got false want true`; the following preview and
acceptance checks consequently failed as well. I changed the response shape to
match the actual executable contract. The next run passed all invite checks.

**What I rejected:** Keeping the nested `invite.token` shape because it looked
reasonable from an API-design perspective. The executable contract is the
evidence that matters for this task.

**What would change my mind:** A changed API contract or test that standardizes the
token under a different response property.

---

### 9. Pagination validates boundaries instead of silently clamping them

**What I chose:** Reject invalid `limit` values and negative offsets, while allowing
a large valid offset to return an empty result rather than converting it into an
error.

**Why:** The API suite checks `limit=0`, `limit=-1`, and `limit=99999` as 400 cases,
while `offset=99999` must be 200. I initially had a null/undefined mistake when
reading `URLSearchParams`: `.get()` returns `null` when the parameter is absent.
Changing the default checks to `=== null` made the normal request and boundary
cases pass.

**What I rejected:** Clamping invalid values to a safe range. That hides caller
mistakes and would contradict the explicit boundary tests.

**What would change my mind:** A pagination contract that explicitly requires
server-side clamping instead of validation.

---

## Where this repo argues with itself

I found one important place where the executable contract was more precise than my
initial implementation assumption.

The invite response was initially implemented as:

`invite.token`

but the executable API test reads:

`inviteToken`

I built against the executable contract after the first run failed. This was not
a disagreement that required changing the database model; it was a response-shape
decision discovered through the test.

I did **not** invent a second documentation contradiction where I could not verify
both sides from the files available in `starter/`. In particular, `PERMISSIONS.md`
was not present in the candidate working directory when I checked, so I did not
claim a contradiction from memory or from an unverified document.

---

## Deliberately not built

I deliberately kept the implementation within the supplied API and console
scope rather than adding unrelated infrastructure.

I did not build:

- a separate authentication service;
- an external invite/email delivery provider;
- a refresh-token rotation system beyond the supplied authentication surface;
- a background job system for session expiry or invite expiry;
- a second permission engine in the frontend;
- hard-coded role/permission configuration in React;
- an additional caching layer for resolved permissions;
- an external audit-log service.

The reason is scope and correctness: the repository already supplies the single
process/server structure, database schema, permission catalogue, API contract,
and frontend contract. Adding another authority or asynchronous subsystem would
create another source of truth without being required by the tested contract.

The frontend should consume server-resolved permissions rather than independently
reimplement authorization.

---

## Evidence summary

Final public API measurement:

`node scripts/check-api.js` -> **66 passed, 0 failed**

Permission resolution measurement:

`node scripts/check-permissions.js` -> **35 passed, 0 failed**

JWT verification measurement:

`node scripts/check-jwt.js` -> **43 passed, 0 failed**

The most useful implementation bugs discovered during the work were the initial
permission result shape/reason mismatches, the Windows database-loader path
problem, the URLSearchParams `null` handling mistake, and the invite response
property mismatch. In each case the implementation was corrected against the
observed contract rather than changing the tests.

---