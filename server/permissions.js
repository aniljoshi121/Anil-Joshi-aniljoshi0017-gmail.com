// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// Every answer is built from the database on every call: the permission catalogue,
// the role baseline, and the caller's grants that are active right now. Nothing is
// hardcoded here, so a role or permission that only exists in the database (the
// personalised fixture has one of each) resolves exactly like the documented ones.
//
// Order of evaluation for one permission at one scope (PERMISSIONS.md §3):
//   1. no membership / suspended  -> deny everything
//   2. any applicable deny grant  -> deny, explicit (D1: deny wins at any scope)
//   3. role baseline              -> allow, source role:<role>
//   4. applicable allow grant     -> allow, source grant:<id>
//   5. otherwise                  -> deny, implicit (D4)

import { forbidden } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

const ALLOW_ROLE = (role) => ({ effect: 'allow', source: `role:${role}`, reason: null });
const ALLOW_GRANT = (id) => ({ effect: 'allow', source: `grant:${id}`, reason: null });
const DENY_GRANT = (id) => ({ effect: 'deny', source: `grant:${id}`, reason: 'explicit_deny' });
const DENY = (reason) => ({ effect: 'deny', source: null, reason });

// Does a grant pattern ('*', 'device:*' or an exact key) cover this permission?
export function patternCovers(pattern, permission) {
  if (pattern === '*') return true;
  if (pattern.endsWith(':*')) return permission.startsWith(pattern.slice(0, -1));
  return pattern === permission;
}

export function catalogue(db) {
  return db.prepare('SELECT key FROM permissions ORDER BY key').pluck().all();
}

// Everything one resolution needs, fetched once. Three small queries regardless of
// how many devices are then evaluated against it.
function loadInputs(db, { userId, orgId, now }) {
  const permissions = catalogue(db);

  const membership = db.prepare(
    `SELECT m.role, m.status
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id AND o.deleted_at IS NULL
      WHERE m.org_id = ? AND m.user_id = ?`
  ).get(orgId, userId);

  if (!membership || membership.status === 'removed' || membership.status === 'invited') {
    return { permissions, role: null, blocked: 'not_a_member' };
  }
  if (membership.status === 'suspended') {
    return { permissions, role: membership.role, blocked: 'suspended' };
  }

  const baseline = new Set(
    db.prepare('SELECT permission FROM role_permissions WHERE role = ?').pluck().all(membership.role)
  );

  // Half-open window (D7): starts_at <= now < expires_at. Timestamps are canonical
  // ISO-8601 UTC, so string comparison is chronological comparison.
  const at = now.toISOString();
  const grantRows = db.prepare(
    `SELECT g.id, g.device_id AS deviceId, g.effect, gp.permission AS pattern
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
       LEFT JOIN devices d ON d.id = g.device_id
      WHERE g.org_id = ? AND g.user_id = ?
        AND g.revoked_at IS NULL
        AND (g.starts_at IS NULL OR g.starts_at <= ?)
        AND (g.expires_at IS NULL OR g.expires_at > ?)
        AND (g.device_id IS NULL OR (d.org_id = g.org_id AND d.deleted_at IS NULL))
      ORDER BY g.id`
  ).all(orgId, userId, at, at);

  return { permissions, role: membership.role, blocked: null, baseline, grants: grantRows };
}

// Resolve one permission against the loaded inputs.
//   scope = { deviceId }        exact check for one device
//   scope = { orgWide: true }   only org-wide grants count (used for granting authority)
//   scope = {}                  org-level view: the union across devices
function decide(inputs, permission, scope) {
  if (inputs.blocked) return DENY(inputs.blocked);

  const relevant = inputs.grants.filter((g) => patternCovers(g.pattern, permission));
  const orgWide = relevant.filter((g) => g.deviceId === null);
  const onDevice = scope.deviceId ? relevant.filter((g) => g.deviceId === scope.deviceId) : [];

  // D1: an explicit deny wins over everything, and an org-wide deny cannot be
  // carved out by a device-scoped allow.
  const deny = [...orgWide, ...onDevice].find((g) => g.effect === 'deny');
  if (deny) return DENY_GRANT(deny.id);

  if (inputs.baseline.has(permission)) return ALLOW_ROLE(inputs.role);

  const allow = [...orgWide, ...onDevice].find((g) => g.effect === 'allow');
  if (allow) return ALLOW_GRANT(allow.id);

  // Org-level view: allowed if some device-scoped allow is not cancelled by a
  // deny on that same device.
  if (!scope.deviceId && !scope.orgWide) {
    const deniedDevices = new Set(
      relevant.filter((g) => g.deviceId && g.effect === 'deny').map((g) => g.deviceId)
    );
    const viaDevice = relevant.find(
      (g) => g.deviceId && g.effect === 'allow' && !deniedDevices.has(g.deviceId)
    );
    if (viaDevice) return ALLOW_GRANT(viaDevice.id);
  }

  return DENY('implicit');
}

function resolveAll(inputs, scope) {
  const out = {};
  for (const permission of inputs.permissions) out[permission] = decide(inputs, permission, scope);
  return out;
}

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const inputs = loadInputs(db, { userId, orgId, now });
  return { role: inputs.role, permissions: resolveAll(inputs, deviceId ? { deviceId } : {}) };
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
// One set of queries, then pure evaluation per device.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const inputs = loadInputs(db, { userId, orgId, now });
  const byDevice = {};
  for (const deviceId of deviceIds) byDevice[deviceId] = resolveAll(inputs, { deviceId });
  return { role: inputs.role, byDevice };
}

export function can(db, ctx, permission, deviceId = null) {
  return check(db, ctx, permission, deviceId).effect === 'allow';
}

function check(db, ctx, permission, deviceId, scope = deviceId ? { deviceId } : {}) {
  const inputs = loadInputs(db, { userId: ctx.userId, orgId: ctx.orgId, now: new Date() });
  if (!inputs.permissions.includes(permission)) return DENY('implicit');
  return decide(inputs, permission, scope);
}

// Map an engine answer onto the reason the API reports.
function refusalReason(answer) {
  if (answer.reason === 'explicit_deny' || answer.reason === 'suspended') return answer.reason;
  return 'missing_permission';
}

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId = null) {
  const answer = check(db, ctx, permission, deviceId);
  if (answer.effect !== 'allow') {
    throw forbidden(`missing permission ${permission}`, refusalReason(answer));
  }
  return answer;
}

// No privilege laundering (D9): you may only grant authority you hold at that scope.
// An org-wide grant needs org-wide authority; a device grant needs it on that device.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const inputs = loadInputs(db, { userId: ctx.userId, orgId: ctx.orgId, now: new Date() });
  const scope = deviceId ? { deviceId } : { orgWide: true };

  for (const pattern of patterns) {
    const covered = inputs.permissions.filter((p) => patternCovers(pattern, p));
    for (const permission of covered) {
      if (decide(inputs, permission, scope).effect !== 'allow') {
        throw forbidden(`you cannot grant ${permission}: you do not hold it at this scope`, 'missing_permission');
      }
    }
  }
}

// The compound check: session:start AND the permission for the requested mode, both on
// the same device. The two refusals carry different reasons so the caller can tell
// which half was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  const inputs = loadInputs(db, { userId: ctx.userId, orgId: ctx.orgId, now: new Date() });

  const start = decide(inputs, 'session:start', { deviceId });
  if (start.effect !== 'allow') {
    throw forbidden('missing permission session:start on this device', 'missing_permission');
  }

  const device = decide(inputs, modePermission, { deviceId });
  if (device.effect !== 'allow') {
    throw forbidden(`missing permission ${modePermission} on this device`, 'missing_device_permission');
  }

  return { start, device, role: inputs.role };
}
