# BUILD-LOG

**How this log was written.** The task went live with a same-day deadline, and I did not commit
this log while I worked, which is my mistake. The entries below were written on the evening of
27 Sep from my terminal history, the test output, and the commit history, not live. The code for
the engine, routes and console was drafted with an AI assistant (Claude); I ran every suite
myself, and every entry below is something I observed on my machine. Where the first draft was
wrong, I say so.

---

## Phase 0 — orientation

**Setup did not work first time, three times.**

1. `npm install` failed building `better-sqlite3`: `gyp ERR! find VS You need to install the
   latest version of Visual Studio`. I was on Node 24.19.0 and `.nvmrc` says 22. There is no
   prebuilt Windows binary for Node 24, so npm fell back to compiling from source. I expected a
   version mismatch to be a warning, not a hard failure. Installed Node 22.23.3 directly (nvm-windows
   timed out fetching its manifest, `budget 3s`), and `npm install` went through with 0 errors.
2. `npm run db:reset` failed: `'rm' is not recognized`. The script is written for Mac/Linux shells.
   I did not change `package.json` because graders will run it on a Unix shell; locally I delete the
   db files in PowerShell and run `npm run db:load`.
3. `npm run db:load` failed with `ENOENT ... 'D:\D:\new\remoteops\db\schema.sql'`. The drive letter
   appears twice. `new URL(p, import.meta.url).pathname` returns `/D:/new/...` on Windows and Node
   prepends the drive again. Fixed with `fileURLToPath` in `scripts/load-db.js` and
   `server/index.js` (commit `56d7ae7`). Works on every OS, so it is safe to ship.

Starting line: `check-jwt.js` 0/43, everything else failing with the `TODO` stubs.

Also: for a while my edits were "not landing", `git status` kept saying `working tree clean`. I had
opened the files but never saved them. Switched to editing through PowerShell and checking
`git diff` after every change.

## Phase 1 — token verification

`verifyAccessToken` in `server/auth.js` (commit `d46bab9`). 43/43 in `check-jwt.js`.

What I had to understand rather than copy:
- The header is attacker-controlled. The check is `header.alg !== 'HS256'`, a pin, not a denylist
  of bad algorithms, so `alg: none`, `HS512` and `RS256` all fail on the same line.
- The signature is checked before any payload claim is read.
- `timingSafeEqual` throws on buffers of different length, so the length comparison has to come
  first. The case `signature is not base64url` passes because `Buffer.from('!!!', 'base64url')`
  silently drops the invalid characters and returns a shorter buffer: it fails the length check,
  not the decode.
- `exp <= now`, not `<`. `exp exactly now` is a separate test case.
- Staleness (`pv`) is not checked here, because it needs the database. `assertFresh` does that,
  and `context.js` calls it.

## Phase 2 — caller context and the resolution engine

`server/permissions.js`, `server/context.js`. `check-permissions.js` 35/35.

**Open question I had to settle: what is "org-level" for a permission only granted on one device?**
The fixture's viewer has `session:start` only on `lab-mac-01`. If the org-level set ignored
device-scoped grants, her Sessions "Start a session" entry would never appear even though she can
start one. So org-level = union across devices: allowed if some device-scoped allow is not
cancelled by a deny on that same device. But an org-wide deny still wins at org level.

**Second open question: the same union is wrong for granting.** If `assertMayGrant` used the union,
someone holding `device:control` on one device could grant it org-wide. So `decide()` has a third
scope, `{ orgWide: true }`, that counts only org-wide grants and the baseline. That is the
"no laundering" rule applied at the right scope.

`npm run personalisation`: my database has a role `reviewer` and a permission `device:reboot` that
no document mentions. 18/18 passed without any change, because the engine reads `permissions`,
`role_permissions` and `grants` from the tables and has no list of its own.

## Phase 3 — orgs, members, invites

**A decision I reversed.** The first draft of `assertCanModify` in `server/lifecycle.js` followed
PERMISSIONS.md §6 literally: you may only modify someone of strictly lower rank. `check-api.js`
then reported 65/66:

```
FAIL  demoting a NON-last owner is allowed   got 403 want 200
```

Dana (owner) could not demote the second Acme owner. With the strict rule, a second owner can never
be demoted by anyone, so ownership could never be handed over. Changed: owners may modify owners;
everyone else strictly lower. Self-change is still refused separately (`SELF_ROLE_CHANGE`) and the
last owner is still protected (`LAST_OWNER`). 66/66 after. Written up in DECISIONS.md.

**Open question: what happens to grants when someone is removed?** Nothing in the documents says.
If they stay, re-inviting the person later would silently bring back every old grant, because the
membership row is reused (`UNIQUE (org_id, user_id)`). So `removeMembership` in
`server/routes/orgs.js` revokes their grants in that org.

## Phase 4 — devices and grants

Unknown permission: I check `permission_patterns` first, to return `reason: unknown_permission`,
but the foreign key on `grant_permissions` is the real guarantee underneath. `db.js` sets
`foreign_keys = ON` per connection.

`GET /devices/:id` on a device I lack `device:view` for: chose 404, not 403, to match the list
that hides the row. Otherwise the detail route would confirm a device exists that the list hides.

## Phase 5 — sessions

**A guarantee I leaned on instead of coding:** exclusivity. No "is there an active control session?"
check before inserting. The insert runs, and if `one_exclusive_session_per_device` rejects it
(`SQLITE_CONSTRAINT_UNIQUE`) the route answers `409 DEVICE_BUSY` with the holder's id. A
check-then-insert would race; the index cannot.

Sessions past `expires_at` would otherwise keep holding that unique slot forever, so
`expireSessions()` in `server/lifecycle.js` ends them before any session read or insert.

## Phase 6 — audit

Denials are recorded by one wrapper, `audited()` in `server/routes/shared.js`, which calls
`auditDenials`. Success rows are written inside the same transaction as the change, so an action
produces one row, never an "allow" plus a "done". Checked in `check-api.js`: "contains denials" and
"denial carries a reason code" pass.

## Phase 7 — the console

`npx playwright test`: 25/25.

The test I cared most about: "an element vanishes when the server withdraws the permission". It
rewrites the devices response to deny `device:control`, and the button has to disappear. It passes
because `PermButton` in `web/ui.jsx` renders nothing unless the server said allow, and the
Devices view refetches on every mount. There is no role table anywhere under `web/`.

Tried the real thing: signed in with my own email and got "Sign-in failed: invalid email or
password." That is correct: my email is not in the fixture. It also shows the message does not
say whether the account exists.

## Phase 8 — hardening

**A bug in my own process, found by checking the repo from outside.** After pushing the console I
cloned my own repository to check it. The console commit (`1ee10f0`) was there, but
`server/permissions.js`, `context.js`, `lifecycle.js`, `audit.js` and the route files were still the
original stubs: I had skipped the backend commits. Anyone cloning at that point would have had a
console whose every request failed. Committed the backend immediately after. Lesson: test from a
fresh clone, not from my working folder.

**Measured:** `GET /orgs/:org/devices` runs 5 queries whatever the number of devices (the device list,
then catalogue, membership, baseline and grants once, in `resolveDevices`). Each row is then decided
in memory. No per-row query, and the console makes no per-row request.

## Open threads

- A reload always returns to your first org, because nothing about the active org is stored
  client-side (by design, no web storage). Could carry it in the URL.
- Login has no rate limiting.
- File transfer is a permission-gated button that moves nothing.
- `DELETE /sessions/:id` on an already-ended session returns 409; a case could be made for 200.
