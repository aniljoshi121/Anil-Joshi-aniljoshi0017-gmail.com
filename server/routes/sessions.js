// Sessions are records, not remote access: opened, authorised, watched, ended.
//
// Start is a compound check (session:start AND the mode permission, same device).
// control/terminal exclusivity is enforced by the partial unique index, so two
// concurrent requests cannot both win; we translate that violation into DEVICE_BUSY.

import { assertCanStartSession, can, MODE_PERMISSION } from '../permissions.js';
import { expireSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit } from '../audit.js';
import { newId, nowIso } from '../db.js';
import { badRequest, conflict, deviceBusy, forbidden, notFound } from '../http.js';
import { audited, ok, created, pageParams } from './shared.js';

const SESSION_COLUMNS = `s.id, s.org_id, s.user_id, u.email AS user_email, s.device_id, d.name AS device_name,
  s.mode, s.state, s.end_reason, s.started_at, s.expires_at, s.ended_at`;

function loadSession(db, id) {
  return db.prepare(
    `SELECT ${SESSION_COLUMNS} FROM sessions s
       JOIN users u ON u.id = s.user_id
       JOIN devices d ON d.id = s.device_id
      WHERE s.id = ?`
  ).get(id);
}

// A session in the caller's org that the caller may see: their own, or any with
// session:view on its device. Anything else is invisible.
function visibleSession(db, ctx, id) {
  const session = loadSession(db, id);
  if (!session || session.org_id !== ctx.orgId) throw notFound();
  if (session.user_id !== ctx.userId && !can(db, ctx, 'session:view', session.device_id)) throw notFound();
  return session;
}

export function registerSessionRoutes(router, { db }) {
  router.get('/v1/orgs/:org/sessions', audited('session.list', 'org', (ctx, params, res) => {
    if (!can(db, ctx, 'session:view')) throw forbidden('missing permission session:view', 'missing_permission');
    expireSessions(db);
    const { limit, offset } = pageParams(ctx.query, { defaultLimit: 200 });
    const sessions = db.prepare(
      `SELECT ${SESSION_COLUMNS} FROM sessions s
         JOIN users u ON u.id = s.user_id
         JOIN devices d ON d.id = s.device_id
        WHERE s.org_id = ?
        ORDER BY s.state = 'active' DESC, s.started_at DESC
        LIMIT ? OFFSET ?`
    ).all(params.org, limit, offset);
    ok(res, { sessions });
  }, (p) => p.org));

  router.post('/v1/orgs/:org/sessions', audited('session.start', 'device', (ctx, params, res) => {
    const { deviceId, mode } = ctx.body;
    if (!(mode in MODE_PERMISSION)) throw badRequest('mode must be view, control or terminal');
    if (typeof deviceId !== 'string') throw badRequest('deviceId is required');

    const device = db.prepare('SELECT id FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, params.org);
    if (!device) throw notFound();

    const authority = assertCanStartSession(db, ctx, mode, deviceId);

    // Sessions past their TTL must not keep holding the exclusive slot.
    expireSessions(db);

    const id = newId('ses');
    const startedAt = new Date();
    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)`
        ).run(
          id, params.org, ctx.userId, deviceId, mode,
          snapshotAuthority(db, { userId: ctx.userId, orgId: params.org, deviceId, ...authority }),
          startedAt.toISOString(), sessionExpiry(db, params.org, startedAt)
        );
        audit(db, { orgId: params.org, actorId: ctx.userId, action: 'session.start', targetType: 'session', targetId: id, result: 'allow', reasonCode: mode, requestId: ctx.requestId });
      })();
    } catch (err) {
      if (err?.code !== 'SQLITE_CONSTRAINT_UNIQUE') throw err;
      const holder = db.prepare(
        `SELECT id FROM sessions WHERE device_id = ? AND state = 'active' AND mode IN ('control','terminal')`
      ).pluck().get(deviceId);
      throw deviceBusy(`device already has an exclusive session (${holder})`);
    }

    created(res, loadSession(db, id));
  }, () => null));

  router.get('/v1/sessions/:id', audited('session.view', 'session', (ctx, params, res) => {
    expireSessions(db);
    ok(res, visibleSession(db, ctx, params.id));
  }, (p) => p.id));

  // Stop your own session, or anyone's with session:terminate.
  router.delete('/v1/sessions/:id', audited('session.stop', 'session', (ctx, params, res) => {
    expireSessions(db);
    const session = visibleSession(db, ctx, params.id);
    const own = session.user_id === ctx.userId;
    if (!own && !can(db, ctx, 'session:terminate', session.device_id)) {
      throw forbidden('missing permission session:terminate', 'missing_permission');
    }
    if (session.state === 'ended') throw conflict('session has already ended');

    const reason = own ? 'user_stopped' : 'admin_terminated';
    db.transaction(() => {
      db.prepare(`UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ? AND state != 'ended'`)
        .run(reason, nowIso(), params.id);
      audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'session.stop', targetType: 'session', targetId: params.id, result: 'allow', reasonCode: reason, requestId: ctx.requestId });
    })();
    ok(res, loadSession(db, params.id));
  }, (p) => p.id));
}
