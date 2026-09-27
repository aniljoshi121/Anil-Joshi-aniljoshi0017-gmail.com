// Shared domain rules: role ranks, last-owner protection, ending sessions.
//
// roles.rank is modification authority ONLY. Nothing in here answers "can this user do
// X" -- that is permissions.js. This file answers "may this user change that user".

import { badRequest, forbidden, lastOwner } from './http.js';
import { nowIso } from './db.js';

export function roleRanks(db) {
  const rows = db.prepare('SELECT key, rank FROM roles').all();
  return Object.fromEntries(rows.map((r) => [r.key, r.rank]));
}

export function assertRoleExists(db, role) {
  if (typeof role !== 'string' || !(role in roleRanks(db))) {
    throw badRequest('unknown role', 'unknown_role');
  }
}

// You may modify only someone of strictly lower rank, so admin -> admin is refused.
// Owners are the exception: an owner may manage another owner, otherwise a second
// owner could never be demoted and ownership could never be handed over. Self-changes
// are refused separately by the routes, and the last owner is protected separately.
export function assertCanModify(db, callerRole, targetRole) {
  if (callerRole === 'owner') return;
  const ranks = roleRanks(db);
  if (!(ranks[callerRole] > ranks[targetRole])) {
    throw forbidden('you cannot modify a member of equal or higher role', 'insufficient_rank');
  }
}

// Which roles can the caller hand out? An owner can confer anything, including owner.
// Everyone else only roles strictly below their own.
export function assertCanAssign(db, callerRole, newRole) {
  assertRoleExists(db, newRole);
  if (callerRole === 'owner') return;
  const ranks = roleRanks(db);
  if (!(ranks[callerRole] > ranks[newRole])) {
    throw forbidden(`you cannot assign the ${newRole} role`, 'insufficient_rank');
  }
}

// Throws if taking this user out of the owner role would leave the org with no active
// owner. Called before demote, suspend, remove and leave.
export function assertNotLastOwner(db, orgId, userId) {
  const target = db.prepare(
    `SELECT role, status FROM memberships WHERE org_id = ? AND user_id = ?`
  ).get(orgId, userId);
  if (!target || target.role !== 'owner' || target.status !== 'active') return;

  const others = db.prepare(
    `SELECT count(*) FROM memberships
      WHERE org_id = ? AND role = 'owner' AND status = 'active' AND user_id != ?`
  ).pluck().get(orgId, userId);
  if (others === 0) throw lastOwner();
}

// The one implementation of "these sessions are over". Filters combine with AND.
export function endActiveSessions(db, { orgId, userId, deviceId, reason, exceptSessionId }) {
  const where = [`state = 'active'`];
  const args = [];
  if (orgId) { where.push('org_id = ?'); args.push(orgId); }
  if (userId) { where.push('user_id = ?'); args.push(userId); }
  if (deviceId) { where.push('device_id = ?'); args.push(deviceId); }
  if (exceptSessionId) { where.push('id != ?'); args.push(exceptSessionId); }

  return db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
      WHERE ${where.join(' AND ')}`
  ).run(reason, nowIso(), ...args).changes;
}

// Sessions past their TTL are ended lazily, on the next request that looks at
// sessions. Nothing needs a background timer for this to be correct.
export function expireSessions(db) {
  db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = 'session_expired', ended_at = expires_at
      WHERE state = 'active' AND expires_at <= ?`
  ).run(nowIso());
}

// What the session was allowed on, frozen at start. Sessions are grandfathered, so
// this record, not the live grants, is the authority for the session's life.
export function snapshotAuthority(db, { userId, orgId, deviceId, role, start, device }) {
  return JSON.stringify({ userId, orgId, deviceId, role, sessionStart: start, devicePermission: device, at: nowIso() });
}

export function sessionExpiry(db, orgId, from = new Date()) {
  const minutes = db.prepare('SELECT max_session_minutes FROM organizations WHERE id = ?').pluck().get(orgId) ?? 60;
  return new Date(from.getTime() + minutes * 60_000).toISOString();
}
