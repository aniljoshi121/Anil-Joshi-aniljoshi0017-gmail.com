// Small helpers every route file uses: the audited handler wrapper, the session payload
// returned by login/switch/refresh, the refresh cookie, and input validation.

import { auditDenials } from '../audit.js';
import { resolve } from '../permissions.js';
import { issueAccessToken, newRefreshToken, hashRefreshToken, REFRESH_TTL_SECONDS } from '../auth.js';
import { badRequest, send } from '../http.js';
import { newId } from '../db.js';

// Wrap a handler so a refusal inside it is recorded in the audit log.
// `target` picks the audited target id out of the path params.
export function audited(action, targetType, handler, target = () => null) {
  return (ctx, params, res) =>
    auditDenials(ctx.db, ctx, { action, targetType, targetId: target(params) }, () => handler(ctx, params, res));
}

export const ok = (res, body) => send(res, 200, body);
export const created = (res, body) => send(res, 201, body);

// --- validation ------------------------------------------------------------

export function requireString(value, field, { max = 100 } = {}) {
  if (typeof value !== 'string' || value.trim() === '') throw badRequest(`${field} is required`);
  const trimmed = value.trim();
  if (trimmed.length > max) throw badRequest(`${field} must be at most ${max} characters`);
  return trimmed;
}

export function normalizeEmail(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    throw badRequest('a valid email is required');
  }
  return email;
}

// Pagination is validated, never clamped: a nonsense limit is the caller's bug.
export function pageParams(query, { defaultLimit = 50, maxLimit = 500 } = {}) {
  const parse = (name, fallback) => {
    const raw = query.get(name);
    if (raw === null) return fallback;
    if (!/^-?\d+$/.test(raw)) throw badRequest(`${name} must be an integer`);
    return Number(raw);
  };
  const limit = parse('limit', defaultLimit);
  const offset = parse('offset', 0);
  if (limit < 1 || limit > maxLimit) throw badRequest(`limit must be between 1 and ${maxLimit}`);
  if (offset < 0) throw badRequest('offset must be zero or more');
  return { limit, offset };
}

// --- the signed-in payload --------------------------------------------------

export function userOrgs(db, userId) {
  return db.prepare(
    `SELECT o.id, o.name, o.theme, m.role, m.status
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
      WHERE m.user_id = ? AND m.status IN ('active', 'suspended')
      ORDER BY m.joined_at IS NULL, m.joined_at, o.name`
  ).all(userId);
}

// What the console needs after sign-in, org switch or refresh: who you are, which org
// the token is for, your role there, every org you belong to, and the org-level
// resolved permission set that gates the navigation.
export function sessionPayload(db, secret, userId, orgId) {
  const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(userId);
  const membership = db.prepare(
    'SELECT role, perm_version FROM memberships WHERE org_id = ? AND user_id = ?'
  ).get(orgId, userId);

  const token = issueAccessToken({ userId, orgId, role: membership.role, permVersion: membership.perm_version }, secret);
  const { permissions } = resolve(db, { userId, orgId });

  // Roles are reference data (key, label, rank) so the console can offer a role picker.
  // Which permissions a role carries is NOT sent: the console never derives authority.
  const roles = db.prepare('SELECT key, label FROM roles ORDER BY rank DESC').all();

  return {
    token,
    user,
    orgId,
    role: membership.role,
    orgs: userOrgs(db, userId),
    roles,
    permissions,
  };
}

// --- the refresh cookie -----------------------------------------------------

export const REFRESH_COOKIE = 'remoteops_rt';

export function issueRefreshToken(db, userId, familyId = newId('fam')) {
  const raw = newRefreshToken();
  const expiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
  db.prepare(
    `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)`
  ).run(newId('rt'), userId, hashRefreshToken(raw), familyId, expiresAt);
  return raw;
}

export function setRefreshCookie(res, raw) {
  res.setHeader('set-cookie',
    `${REFRESH_COOKIE}=${raw}; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth; Max-Age=${REFRESH_TTL_SECONDS}`);
}

export function clearRefreshCookie(res) {
  res.setHeader('set-cookie', `${REFRESH_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/v1/auth; Max-Age=0`);
}

export function readCookie(req, name) {
  for (const part of (req.headers.cookie ?? '').split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key === name) return rest.join('=');
  }
  return null;
}
