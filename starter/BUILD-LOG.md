# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

### 2026-09-26 14:39 — Phase 0 — orientation

`npm install` completed successfully, but `npm run db:reset` failed because the supplied script uses Unix `rm -f`, which is not available in my PowerShell environment.

Running the underlying `npm run db:load` exposed a second issue in `scripts/load-db.js`: `new URL(...).pathname` produced an invalid Windows path containing `D:\D:\` and `%20`.

Changed the path conversion to use Node's `fileURLToPath(new URL(...))`, then reran the loader successfully.

The database seeded with 3 organizations, 8 users, 10 memberships, 9 devices, 6 grants, 3 sessions, and 7 audit events.

The personalized fixture also added the `reviewer` role and `device:reboot` permission, showing that roles and permissions must be resolved from the database rather than encoded from the documented matrix..

## Phase 0 — orientation

_Installed, reset the database, read the documents, ran the suites against the untouched skeleton.
What did the starting line actually look like, and which failure surprised you?_

## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_

### 2026-09-26 15:02 — Baseline JWT suite

Before implementing `verifyAccessToken`, I expected the JWT suite to fail because the function was still the supplied stub.

Observed: all 43 cases failed with the `NOT_IMPLEMENTED` error, including the valid-token round trip.

The useful part of the failure output was the contract itself: valid claims must survive unchanged, while malformed structure, algorithm substitution, signature failures, expired/missing `exp`, wrong `iss`/`aud`, missing/empty `jti`, and opaque refresh tokens must all become `401 UNAUTHENTICATED`.

This gives me the baseline; I will implement the verifier against these explicit failure modes rather than weakening the test expectations.

### 2026-09-26 15:08 — Verifier implementation

Implemented `verifyAccessToken` using the supplied HS256 signing format.

The first run after implementation passed all 43 JWT cases: valid claims round-tripped, malformed tokens returned 401, algorithm substitution was rejected, signatures were checked with `timingSafeEqual`, `exp == now` was treated as expired, and issuer/audience/jti validation passed.

The baseline had been 0/43; the final result was 43/43. I kept the verifier limited to token authenticity and claim validation rather than putting authorization logic into the JWT.

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._

### 2026-09-26 15:41 — Permission baseline

Ran `node scripts/check-permissions.js` before implementing the permission resolver. The suite stopped immediately in `resolve()` because `server/permissions.js` is still the supplied TODO stub and throws `NOT_IMPLEMENTED`.

The DB inspection showed the personalized fixture has the `reviewer` role and `device:reboot` permission, with a device-scoped allow on `dev_p_bb3398_a` and deny on `dev_p_bb3398_b`. I will use the database tables rather than hard-coding the documented role/permission matrix.

### 2026-09-26 16:13 — Permission resolver passes

Implemented the permission resolution engine from the database schema and the documented resolution rules.

The first useful implementation exposed two mismatches with the repository's test contract: the resolver needed `permissions[permission].effect` objects rather than a flat array, and the expected implicit-deny reason was `implicit`. I also corrected the non-member reason to `not_a_member` after the test exposed that contract.

The final resolver checks membership, loads the permission catalogue and role baseline from the DB, evaluates active grants including exact and wildcard patterns, applies device scope and half-open time windows, and gives explicit denies precedence over allows.

Implemented `can()` as a thin wrapper over `resolve()`, and implemented the compound session check so `session:start` and the requested device mode permission are checked separately.

Measurement: `node scripts/check-permissions.js` → 35 passed, 0 failed.

The personalized fixture was useful here: `device:reboot` exists only in the personalized database, with an allow on one device and deny on another, so the implementation remains database-driven rather than relying on the prose role matrix.

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
