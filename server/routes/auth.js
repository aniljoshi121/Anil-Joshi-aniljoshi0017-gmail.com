// Sign-in, refresh, org switching, and "who am I".

import { verifyPassword, hashPassword, hashRefreshToken } from '../auth.js';
import { unauthenticated, notFound, badRequest } from '../http.js';
import { nowIso } from '../db.js';
import {
  ok, sessionPayload, userOrgs, issueRefreshToken, setRefreshCookie, clearRefreshCookie,
  readCookie, REFRESH_COOKIE,
} from './shared.js';

// Hash of a password nobody has, so a login for an unknown email costs the same scrypt
// work as a wrong password and response timing does not reveal which emails exist.
const DECOY_HASH = hashPassword('decoy-password-never-valid');
const BAD_LOGIN = 'invalid email or password';

// Pick the org a fresh sign-in lands in: the one asked for, else the first active one.
function landingOrg(db, userId, requested) {
  const orgs = userOrgs(db, userId);
  if (requested) {
    if (!orgs.some((o) => o.id === requested)) throw notFound();
    return requested;
  }
  const first = orgs.find((o) => o.status === 'active') ?? orgs[0];
  if (!first) throw unauthenticated('you are not a member of any organization');
  return first.id;
}

export function registerAuthRoutes(router, { db, secret }) {
  router.post('/v1/auth/login', (ctx, _params, res) => {
    const email = typeof ctx.body.email === 'string' ? ctx.body.email.trim().toLowerCase() : '';
    const password = typeof ctx.body.password === 'string' ? ctx.body.password : '';

    const user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(email);
    const valid = verifyPassword(password, user?.password_hash ?? DECOY_HASH);
    // Same message for "no such account" and "wrong password": no enumeration oracle.
    if (!user || !valid) throw unauthenticated(BAD_LOGIN);

    const orgId = landingOrg(db, user.id, ctx.body.orgId);
    setRefreshCookie(res, issueRefreshToken(db, user.id));
    ok(res, sessionPayload(db, secret, user.id, orgId));
  });

  // Rotating refresh. Presenting a token that was already rotated is treated as theft:
  // the whole family is revoked and the caller has to sign in again.
  router.post('/v1/auth/refresh', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, REFRESH_COOKIE);
    if (!raw) throw unauthenticated('no refresh token');

    const row = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
    if (!row) throw unauthenticated('invalid refresh token');

    const now = nowIso();
    if (row.revoked_at) {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL').run(now, row.family_id);
      clearRefreshCookie(res);
      throw unauthenticated('refresh token reuse detected; sign in again');
    }
    if (row.expires_at <= now) throw unauthenticated('refresh token expired');

    const orgId = landingOrg(db, row.user_id, ctx.body.orgId);
    const next = db.transaction(() => {
      db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?').run(now, row.id);
      return issueRefreshToken(db, row.user_id, row.family_id);
    })();

    setRefreshCookie(res, next);
    ok(res, sessionPayload(db, secret, row.user_id, orgId));
  });

  router.post('/v1/auth/logout', (ctx, _params, res) => {
    const raw = readCookie(ctx.req, REFRESH_COOKIE);
    if (raw) {
      const row = db.prepare('SELECT family_id FROM refresh_tokens WHERE token_hash = ?').get(hashRefreshToken(raw));
      if (row) db.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL').run(nowIso(), row.family_id);
    }
    clearRefreshCookie(res);
    ok(res, { ok: true });
  });

  // Switch org: a new token scoped to the requested org. Not a filter over one token.
  router.post('/v1/auth/token', (ctx, _params, res) => {
    const orgId = ctx.body.orgId;
    if (typeof orgId !== 'string' || !orgId) throw badRequest('orgId is required');
    const orgs = userOrgs(db, ctx.userId);
    if (!orgs.some((o) => o.id === orgId)) throw notFound();
    ok(res, sessionPayload(db, secret, ctx.userId, orgId));
  });

  router.get('/v1/auth/me', (ctx, _params, res) => {
    const { token: _unused, ...rest } = sessionPayload(db, secret, ctx.userId, ctx.orgId);
    ok(res, rest);
  });
}
