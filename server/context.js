// Per-request context: turn a bearer token into an authenticated caller.
//
// The token's `org` claim is the ONLY org the caller may address. A path naming any
// other org is a 404 before a single permission is evaluated, so isolation is
// structural rather than a WHERE clause each route has to remember.

import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

export function bearerToken(req) {
  const header = req.headers.authorization ?? '';
  const match = /^Bearer\s+(\S+)$/i.exec(header);
  return match ? match[1] : null;
}

export function authenticate(db, secret) {
  const findMembership = db.prepare(
    `SELECT m.id, m.org_id, m.user_id, m.role, m.status, m.perm_version
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
      WHERE m.org_id = ? AND m.user_id = ?`
  );

  return function buildContext(req, params = {}) {
    const token = bearerToken(req);
    if (!token) throw unauthenticated('missing bearer token');

    const claims = verifyAccessToken(token, secret);

    // A removed (or never-accepted) membership is not a member at all: 401.
    // A suspended one still authenticates; the engine then denies everything, so
    // requests get a 403 with an empty permission set.
    const membership = findMembership.get(claims.org, claims.sub);
    if (!membership || membership.status === 'removed' || membership.status === 'invited') {
      throw unauthenticated('not a member of this org');
    }

    // Role or grant changes bump perm_version, so the old token stops working on the
    // very next request rather than at expiry.
    assertFresh(claims, membership);

    // Structural isolation: the token is scoped to one org and cannot name another.
    if (params.org !== undefined && params.org !== claims.org) throw notFound();

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}
