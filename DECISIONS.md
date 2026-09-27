# DECISIONS

One section per decision that a reviewer might reasonably have made differently.

---

### Owners may modify other owners; everyone else only strictly lower ranks

**What I chose:** `assertCanModify` in `server/lifecycle.js` returns early for an owner caller;
every other role needs a strictly higher rank than the target.
**Why:** my first version followed PERMISSIONS.md §6 exactly ("modify a user of equal role → 403").
`check-api.js` then failed `demoting a NON-last owner is allowed` with `got 403 want 200`. Under the
strict rule a second owner can never be demoted by anyone, so ownership can never be handed over.
Logged in BUILD-LOG.md, Phase 3.
**What I rejected:** the literal rule. It is simple and symmetric, but it makes "owner" a one-way
door.
**What would change my mind:** a requirement that ownership transfers only through a dedicated
flow, for example the outgoing owner demoting themselves. Then owner→owner edits could be refused.

---

### The org-level permission set is the union across devices, but granting authority is not

**What I chose:** `decide()` in `server/permissions.js` has three scopes. `{ deviceId }` is the
exact check. `{}` is org-level: allowed if the baseline or an org-wide allow holds it, or some
device-scoped allow does on a device with no deny for it. `{ orgWide: true }` counts only org-wide
grants and the baseline, and is used only by `assertMayGrant`.
**Why:** the fixture viewer holds `session:start` only on `lab-mac-01`. Without the union, her
"Start a session" entry never appears although she can start one. But using the same union in
`assertMayGrant` would let someone with `device:control` on one device grant it org-wide.
**What I rejected:** a single org-level scope for both. Whichever way it is set, one of the two
cases above is wrong.
**What would change my mind:** a hidden-tier case expecting the org-level view to show only
org-wide authority. Then the console entry would need a separate per-device signal.

---

### Removing a member also revokes their grants in that org

**What I chose:** `removeMembership` in `server/routes/orgs.js` sets the membership to `removed`,
revokes the user's grants in that org, bumps `perm_version`, and ends their sessions with
`membership_removed`.
**Why:** `memberships` has `UNIQUE (org_id, user_id)`, so accepting a later invite reuses the row
(`server/routes/invites.js`, the `existing` branch). If the grants stayed, a rehire would silently
get back every allow, and every deny, from their previous stint. The documents do not cover it.
**What I rejected:** leaving grants alone because a removed membership already makes them inert.
True while removed, but false the moment the person is re-invited.
**What would change my mind:** a product requirement that a reinstated person keeps their
previous exceptions. That would be better done as an explicit "restore" action than as a side
effect.

---

### A device without `device:view` is a 404 on its detail route, not a 403

**What I chose:** `visibleDevice()` in `server/routes/devices.js` throws `notFound()` when the
caller's resolved `device:view` is not allow. Rename, decommission and transfer go through the same
function first.
**Why:** the list hides the row entirely (`check-api.js`: "kiosk-lobby-01 is ABSENT"). A 403 on
`GET /devices/dev_kiosk_lobby_01` would confirm the device exists, which is the leak §5 warns about.
**What I rejected:** 403. The BRIEF table lists `device:view` as the required permission, which
reads like "visible but forbidden". I think the visibility rule should win for this one permission,
because it is the permission that means "you can see it".
**What would change my mind:** a hidden-tier test asserting 403 there. It would be a one-line change
in `visibleDevice`.

---

### Exclusive sessions are enforced by the index, and expired sessions are ended lazily

**What I chose:** `POST /sessions` inserts without checking first; `SQLITE_CONSTRAINT_UNIQUE` from
`one_exclusive_session_per_device` becomes `409 DEVICE_BUSY` with the holder id.
`expireSessions()` ends sessions whose `expires_at <= now` before any session read or insert.
**Why:** a check-then-insert races under two parallel requests; the partial unique index cannot.
`check-api.js` "2nd control on same device -> 409" and "concurrent VIEW on same device -> 201"
both pass. Without the lazy expiry, a session past its TTL would still be `active` and would hold
the unique slot forever.
**What I rejected:** a background timer. It adds a moving part, and between ticks an expired session
would still block the device.
**What would change my mind:** needing an accurate `ended_at` in reports without anyone touching
sessions. Right now I set `ended_at = expires_at` so the recorded time is still correct.

---

### No cache of resolved permissions

**What I chose:** every `resolve`, `resolveDevices`, `can` and `assertCan` reads the tables again.
`resolveDevices` does it once per request: 5 queries for the device list regardless of row count.
**Why:** grants expire by time (half-open windows) and change by revoke, so a cache would need
invalidation on both time and writes. The queries are small and use the
`grants_for_resolution` index. Nothing I measured was slow enough to justify the risk.
**What I rejected:** a per-`(userId, orgId)` cache keyed by `perm_version`. It is safe for revokes
and role changes (both bump the version) but not for a grant reaching `expires_at`, which bumps
nothing. It would need a TTL no longer than the nearest expiry.
**What would change my mind:** a measured slow request with many devices or grants.

---

### The console receives role labels, never role permissions

**What I chose:** `sessionPayload` in `server/routes/shared.js` returns `roles: [{ key, label }]` for
the role picker and invite form. Every gate in `web/` reads the server's resolved `permissions`
(`allowed()` and `PermButton` in `web/ui.jsx`).
**Why:** the architecture test "an element vanishes when the server withdraws the permission"
rewrites the response and expects the button to go. It passes because nothing in `web/` knows
what a role can do.
**What I rejected:** hardcoding the five role names in the dropdown. It would miss the database's
extra role (`reviewer` in my fixture).
**What would change my mind:** nothing about the rule. Only the list's shape could change.

---

### Login does the same work for unknown accounts and wrong passwords

**What I chose:** `POST /auth/login` in `server/routes/auth.js` runs `verifyPassword` against a
decoy hash when the email does not exist, and returns the same `invalid email or password`.
**Why:** identical text alone is not enough if an unknown email returns in 1 ms and a real one
takes a scrypt's worth of time. The UI test "an unknown account is refused without revealing
whether it exists" covers the text; the decoy covers the timing.
**What I rejected:** returning early for an unknown email. It is faster but it is an enumeration
oracle.
**What would change my mind:** nothing; this is cheap.

---

## Where this repo argues with itself

1. **Owner vs owner.** PERMISSIONS.md §6: "modify a user of equal role (admin → admin) | `403`".
   `check-api.js`: "demoting a NON-last owner is allowed" expects 200. I built to the test and argued
   it above.
2. **Which permission gates the device detail.** PERMISSIONS.md §5: "a resource the caller cannot see
   is a `404`, never a `403`". BRIEF.md §5.1 lists `GET /devices/{id}` as requiring `device:view`,
   and §5 says a visible resource without the permission is a 403. For `device:view` those two
   collide. I chose 404 (argued above).
3. **End reasons.** The schema's `sessions.end_reason` allows `superseded`; PERMISSIONS.md §7's table
   of what ends a session has no such trigger. Nothing in my build produces it.
4. **Invite token hashing.** AUTH-DATA-MODEL.md §6 says the invite stores `sha256(token)`; the shipped
   `server/auth.js` uses HMAC-SHA256 with an app key and separate domains for refresh and invite
   tokens, and argues for it in its comments. I kept the shipped HMAC. A keyed hash is stronger than
   a plain one if the database leaks.
5. **Where staleness is checked.** BRIEF.md §3 lists "a stale permission version" among the things
   `verifyAccessToken` must reject. It can't: it has no database. The shipped code splits it into
   `assertFresh`, which `server/context.js` calls, and `check-jwt.js` has no staleness case.
6. **Stale citations.** `server/audit.js` and the schema call append-only audit "invariant 10";
   PERMISSIONS.md §9 numbers it 9 (10 is "the matrix exists in one place").
   `scripts/check-permissions.js` cites §11 and §12, which do not exist.

## Deliberately not built

- **File transfer.** The Transfer files button is gated on `device:file_transfer` and does nothing
  but say so. Moving files would be real remote access, which the ground rules forbid.
- **Remembering the active org across a reload.** A reload returns you to your first org. Storing it
  would need web storage or a readable cookie, and the rules keep tokens and state out of both.
- **Search and pagination in the console**, beyond "load older" on the audit log. The fixture is small.
- **Rate limiting on login.** Worth doing before real use; out of scope for the time I had.

## Tools and sources

- **Claude (Anthropic):** used throughout. It explained the specs, and it drafted
  `verifyAccessToken`, the permission engine, context, lifecycle, audit, all routes, and the React
  console. I ran every test suite myself, fixed my environment problems, reviewed the code, and
  committed it. I can explain each file.
- **Starter dependencies:** better-sqlite3, React, Vite, Playwright.
- **Google Fonts:** IBM Plex Sans, loaded in `web/index.html` with a system-font fallback.
