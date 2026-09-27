// Devices and grants.
//
// Every device row carries the caller's resolved permissions for THAT device, so the
// console never needs a follow-up request per row and never re-derives the rules.

import { assertCan, assertMayGrant, resolve, resolveDevices } from '../permissions.js';
import { endActiveSessions } from '../lifecycle.js';
import { audit } from '../audit.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { badRequest, conflict, forbidden, notFound, HttpError, normalizeTs } from '../http.js';
import { audited, ok, created, requireString } from './shared.js';

const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];

const deviceRow = (d, permissions) => ({ id: d.id, name: d.name, kind: d.kind, online: d.online === 1, permissions });

// A live device in this org, or 404. Another org's device and a missing one look the same.
function findDevice(db, orgId, deviceId) {
  const device = db.prepare(
    'SELECT id, org_id, name, kind, online FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL'
  ).get(deviceId, orgId);
  if (!device) throw notFound();
  return device;
}

// A device the caller has device:view on. Without it the device is invisible (404),
// matching the list, which leaves such devices out entirely.
function visibleDevice(db, ctx, deviceId) {
  const device = findDevice(db, ctx.orgId, deviceId);
  const { permissions } = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  if (permissions['device:view'].effect !== 'allow') throw notFound();
  return { device, permissions };
}

function assertUniqueName(db, orgId, name, exceptId = null) {
  const clash = db.prepare(
    'SELECT 1 FROM devices WHERE org_id = ? AND lower(name) = lower(?) AND deleted_at IS NULL AND id IS NOT ?'
  ).get(orgId, name, exceptId);
  if (clash) throw conflict('a device with that name already exists');
}

// Grants that name a device die with the device's membership of this org.
function retireDevice(db, orgId, deviceId) {
  endActiveSessions(db, { orgId, deviceId, reason: 'device_transferred' });
  const holders = db.prepare(
    'SELECT DISTINCT user_id FROM grants WHERE device_id = ? AND org_id = ? AND revoked_at IS NULL'
  ).pluck().all(deviceId, orgId);
  db.prepare('UPDATE grants SET revoked_at = ? WHERE device_id = ? AND org_id = ? AND revoked_at IS NULL').run(nowIso(), deviceId, orgId);
  for (const userId of holders) bumpPermVersion(db, { orgId, userId });
}

function grantView(db, grant) {
  const permissions = db.prepare('SELECT permission FROM grant_permissions WHERE grant_id = ? ORDER BY permission').pluck().all(grant.id);
  const now = nowIso();
  const active = !grant.revoked_at && (!grant.starts_at || grant.starts_at <= now) && (!grant.expires_at || grant.expires_at > now);
  return { ...grant, permissions, active };
}

export function registerDeviceRoutes(router, { db }) {
  // --- devices ---------------------------------------------------------------

  router.get('/v1/orgs/:org/devices', audited('device.list', 'org', (ctx, params, res) => {
    assertCan(db, ctx, 'device:list');
    const devices = db.prepare(
      'SELECT id, name, kind, online FROM devices WHERE org_id = ? AND deleted_at IS NULL ORDER BY name'
    ).all(params.org);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: params.org, deviceIds: devices.map((d) => d.id) });

    // device:list opens the endpoint; device:view decides which rows are in it.
    const visible = devices
      .filter((d) => byDevice[d.id]['device:view'].effect === 'allow')
      .map((d) => deviceRow(d, byDevice[d.id]));
    ok(res, { devices: visible });
  }, (p) => p.org));

  router.get('/v1/orgs/:org/devices/:id', audited('device.view', 'device', (ctx, params, res) => {
    const { device, permissions } = visibleDevice(db, ctx, params.id);
    ok(res, deviceRow(device, permissions));
  }, (p) => p.id));

  router.post('/v1/orgs/:org/devices', audited('device.provision', 'device', (ctx, params, res) => {
    assertCan(db, ctx, 'device:provision');
    const name = requireString(ctx.body.name, 'name');
    const kind = ctx.body.kind;
    if (!KINDS.includes(kind)) throw badRequest(`kind must be one of ${KINDS.join(', ')}`);

    const id = newId('dev');
    db.transaction(() => {
      assertUniqueName(db, params.org, name);
      db.prepare('INSERT INTO devices (id, org_id, name, kind, online) VALUES (?, ?, ?, ?, 0)').run(id, params.org, name, kind);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.provision', targetType: 'device', targetId: id, result: 'allow', requestId: ctx.requestId });
    })();

    const { permissions } = resolve(db, { userId: ctx.userId, orgId: params.org, deviceId: id });
    created(res, deviceRow({ id, name, kind, online: 0 }, permissions));
  }));

  router.patch('/v1/orgs/:org/devices/:id', audited('device.update', 'device', (ctx, params, res) => {
    visibleDevice(db, ctx, params.id);
    assertCan(db, ctx, 'device:update', params.id);
    const name = requireString(ctx.body.name, 'name');

    db.transaction(() => {
      assertUniqueName(db, params.org, name, params.id);
      db.prepare('UPDATE devices SET name = ? WHERE id = ?').run(name, params.id);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.update', targetType: 'device', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    })();
    const { device, permissions } = visibleDevice(db, ctx, params.id);
    ok(res, deviceRow(device, permissions));
  }, (p) => p.id));

  // Decommission: soft delete. Sessions on it end, grants naming it are revoked.
  router.delete('/v1/orgs/:org/devices/:id', audited('device.decommission', 'device', (ctx, params, res) => {
    visibleDevice(db, ctx, params.id);
    assertCan(db, ctx, 'device:provision', params.id);
    db.transaction(() => {
      db.prepare('UPDATE devices SET deleted_at = ? WHERE id = ?').run(nowIso(), params.id);
      retireDevice(db, params.org, params.id);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'device.decommission', targetType: 'device', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    })();
    ok(res, { id: params.id, deleted: true });
  }, (p) => p.id));

  // Transfer needs device:provision in BOTH orgs. The caller must be a member of the
  // target org; if not, the target is invisible (404).
  router.post('/v1/orgs/:org/devices/:id/transfer', audited('device.transfer', 'device', (ctx, params, res) => {
    visibleDevice(db, ctx, params.id);
    assertCan(db, ctx, 'device:provision', params.id);

    const targetOrgId = ctx.body.targetOrgId ?? ctx.body.orgId;
    if (typeof targetOrgId !== 'string' || !targetOrgId) throw badRequest('targetOrgId is required');
    if (targetOrgId === params.org) throw badRequest('device is already in that organization', 'same_org');

    const inTarget = resolve(db, { userId: ctx.userId, orgId: targetOrgId });
    if (inTarget.role === null) throw notFound();
    if (inTarget.permissions['device:provision'].effect !== 'allow') {
      throw forbidden('missing permission device:provision in the target organization', 'missing_permission');
    }

    db.transaction(() => {
      retireDevice(db, params.org, params.id);
      db.prepare('UPDATE devices SET org_id = ? WHERE id = ?').run(targetOrgId, params.id);
      for (const orgId of [params.org, targetOrgId]) {
        audit(db, { orgId, actorId: ctx.userId, action: 'device.transfer', targetType: 'device', targetId: params.id, result: 'allow', reasonCode: `${params.org}->${targetOrgId}`, requestId: ctx.requestId });
      }
    })();
    ok(res, { id: params.id, orgId: targetOrgId });
  }, (p) => p.id));

  // --- grants ----------------------------------------------------------------

  router.get('/v1/orgs/:org/grants', audited('grant.list', 'org', (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const userId = ctx.query.get('userId');
    const rows = db.prepare(
      `SELECT g.id, g.user_id, u.email AS user_email, g.device_id, d.name AS device_name, g.effect,
              g.starts_at, g.expires_at, g.created_by, g.revoked_at, g.created_at
         FROM grants g
         JOIN users u ON u.id = g.user_id
         LEFT JOIN devices d ON d.id = g.device_id
        WHERE g.org_id = ? AND g.revoked_at IS NULL AND (? IS NULL OR g.user_id = ?)
        ORDER BY g.created_at DESC`
    ).all(params.org, userId, userId);
    ok(res, { grants: rows.map((g) => grantView(db, g)) });
  }, (p) => p.org));

  router.post('/v1/orgs/:org/grants', audited('grant.create', 'grant', (ctx, params, res) => {
    assertCan(db, ctx, 'grant:create');
    const { userId, effect, permissions } = ctx.body;
    const deviceId = ctx.body.deviceId ?? null;

    if (typeof userId !== 'string' || !userId) throw badRequest('userId is required');
    if (effect !== 'allow' && effect !== 'deny') throw badRequest('effect must be allow or deny');
    if (!Array.isArray(permissions) || permissions.length === 0) throw badRequest('permissions must be a non-empty list');
    if (permissions.some((p) => typeof p !== 'string')) throw badRequest('permissions must be strings');

    // Checked up front for a clear reason code. The foreign key on grant_permissions
    // enforces the same rule underneath, so this cannot silently drift.
    const known = new Set(db.prepare('SELECT pattern FROM permission_patterns').pluck().all());
    const unknown = permissions.filter((p) => !known.has(p));
    if (unknown.length) throw badRequest(`unknown permission: ${unknown.join(', ')}`, 'unknown_permission');

    if (deviceId !== null) findDevice(db, params.org, deviceId);
    const target = db.prepare(`SELECT 1 FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`).get(params.org, userId);
    if (!target) throw notFound();

    const startsAt = normalizeTs(ctx.body.startsAt, 'startsAt');
    const expiresAt = normalizeTs(ctx.body.expiresAt, 'expiresAt');
    if (expiresAt && expiresAt <= nowIso()) throw new HttpError(400, 'GRANT_EXPIRED', 'expiresAt is already in the past', 'expired_grant');
    if (startsAt && expiresAt && expiresAt <= startsAt) throw badRequest('expiresAt must be after startsAt');

    if (userId === ctx.userId) throw forbidden('you cannot grant permissions to yourself', 'self_grant');
    assertMayGrant(db, ctx, permissions, deviceId);

    const id = newId('grt');
    const unique = [...new Set(permissions)];
    db.transaction(() => {
      db.prepare(
        `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(id, params.org, userId, deviceId, effect, startsAt, expiresAt, ctx.userId);
      const addPermission = db.prepare('INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)');
      for (const p of unique) addPermission.run(id, p);
      bumpPermVersion(db, { orgId: params.org, userId });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'grant.create', targetType: 'grant', targetId: id, result: 'allow', reasonCode: `${effect}:${unique.join(',')}`, requestId: ctx.requestId });
    })();

    const grant = db.prepare('SELECT * FROM grants WHERE id = ?').get(id);
    created(res, grantView(db, grant));
  }));

  router.delete('/v1/orgs/:org/grants/:id', audited('grant.revoke', 'grant', (ctx, params, res) => {
    assertCan(db, ctx, 'grant:revoke');
    const grant = db.prepare('SELECT id, user_id FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL').get(params.id, params.org);
    if (!grant) throw notFound();

    db.transaction(() => {
      db.prepare('UPDATE grants SET revoked_at = ? WHERE id = ?').run(nowIso(), params.id);
      bumpPermVersion(db, { orgId: params.org, userId: grant.user_id });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'grant.revoke', targetType: 'grant', targetId: params.id, result: 'allow', requestId: ctx.requestId });
    })();
    ok(res, { id: params.id, revoked: true });
  }, (p) => p.id));
}
