// Organizations, members, effective permissions and the audit log.

import { assertCan, resolve } from '../permissions.js';
import {
  assertCanModify, assertCanAssign, assertNotLastOwner, endActiveSessions,
} from '../lifecycle.js';
import { audit } from '../audit.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { conflict, notFound, forbidden, selfRoleChange } from '../http.js';
import { audited, ok, created, requireString, pageParams, userOrgs } from './shared.js';

// A new org gets the next theme not already used by the creator's other orgs, so two
// orgs side by side never look the same.
const THEMES = ['cobalt', 'amber', 'emerald', 'rose', 'violet', 'slate'];

function pickTheme(db, userId) {
  const used = new Set(userOrgs(db, userId).map((o) => o.theme));
  return THEMES.find((t) => !used.has(t)) ?? THEMES[used.size % THEMES.length];
}

// A member the caller is allowed to know about in this org, or 404.
function findMember(db, orgId, userId) {
  const member = db.prepare(
    `SELECT m.user_id, m.role, m.status FROM memberships m
      WHERE m.org_id = ? AND m.user_id = ? AND m.status IN ('active', 'suspended')`
  ).get(orgId, userId);
  if (!member) throw notFound();
  return member;
}

// Removing someone from an org: the membership goes, their live sessions end, and their
// grants here are revoked so a later re-invite starts clean instead of silently
// reviving old authority.
function removeMembership(db, orgId, userId, reason) {
  db.prepare(`UPDATE memberships SET status = 'removed' WHERE org_id = ? AND user_id = ?`).run(orgId, userId);
  db.prepare(`UPDATE grants SET revoked_at = ? WHERE org_id = ? AND user_id = ? AND revoked_at IS NULL`).run(nowIso(), orgId, userId);
  bumpPermVersion(db, { orgId, userId });
  endActiveSessions(db, { orgId, userId, reason });
}

export function registerOrgRoutes(router, { db }) {
  // --- organizations -------------------------------------------------------

  router.get('/v1/orgs', (ctx, _params, res) => {
    ok(res, { orgs: userOrgs(db, ctx.userId) });
  });

  router.post('/v1/orgs', (ctx, _params, res) => {
    const name = requireString(ctx.body.name, 'name');
    const id = newId('org');
    const theme = pickTheme(db, ctx.userId);

    db.transaction(() => {
      const clash = db.prepare(
        `SELECT 1 FROM organizations o JOIN memberships m ON m.org_id = o.id
          WHERE m.user_id = ? AND m.status IN ('active','suspended') AND o.deleted_at IS NULL
            AND lower(o.name) = lower(?)`
      ).get(ctx.userId, name);
      if (clash) throw conflict('you already belong to an organization with that name');

      db.prepare('INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)').run(id, name, theme);
      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, 'owner', 'active', ?)`
      ).run(newId('mem'), id, ctx.userId, nowIso());
      audit(db, { orgId: id, actorId: ctx.userId, action: 'org.create', targetType: 'org', targetId: id, result: 'allow', requestId: ctx.requestId });
    })();

    created(res, { id, name, theme, role: 'owner' });
  });

  router.patch('/v1/orgs/:org', audited('org.update', 'org', (ctx, params, res) => {
    assertCan(db, ctx, 'org:update');
    const name = requireString(ctx.body.name, 'name');
    db.transaction(() => {
      db.prepare('UPDATE organizations SET name = ? WHERE id = ?').run(name, params.org);
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'org.update', targetType: 'org', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    })();
    ok(res, db.prepare('SELECT id, name, theme FROM organizations WHERE id = ?').get(params.org));
  }, (p) => p.org));

  // Soft delete. Every member's token goes stale and every live session ends.
  router.delete('/v1/orgs/:org', audited('org.delete', 'org', (ctx, params, res) => {
    assertCan(db, ctx, 'org:delete');
    db.transaction(() => {
      db.prepare('UPDATE organizations SET deleted_at = ? WHERE id = ?').run(nowIso(), params.org);
      db.prepare('UPDATE memberships SET perm_version = perm_version + 1 WHERE org_id = ?').run(params.org);
      endActiveSessions(db, { orgId: params.org, reason: 'membership_removed' });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'org.delete', targetType: 'org', targetId: params.org, result: 'allow', requestId: ctx.requestId });
    })();
    ok(res, { id: params.org, deleted: true });
  }, (p) => p.org));

  // --- members ---------------------------------------------------------------

  router.get('/v1/orgs/:org/members', audited('member.list', 'org', (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const members = db.prepare(
      `SELECT u.id, u.id AS user_id, u.email, u.name, m.role, m.status, m.joined_at
         FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND m.status IN ('active', 'suspended')
        ORDER BY u.name`
    ).all(params.org);
    ok(res, { members });
  }, (p) => p.org));

  // Leaving is registered before /members/:userId so 'me' is never read as an id.
  router.delete('/v1/orgs/:org/members/me', audited('member.leave', 'user', (ctx, params, res) => {
    db.transaction(() => {
      assertNotLastOwner(db, params.org, ctx.userId);
      removeMembership(db, params.org, ctx.userId, 'membership_removed');
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.leave', targetType: 'user', targetId: ctx.userId, result: 'allow', requestId: ctx.requestId });
    })();
    ok(res, { userId: ctx.userId, status: 'removed' });
  }));

  // Change role. Grandfathering: this bumps perm_version but ends no sessions.
  router.patch('/v1/orgs/:org/members/:userId', audited('member.role_update', 'user', (ctx, params, res) => {
    assertCan(db, ctx, 'user:role:update');
    const target = findMember(db, params.org, params.userId);
    if (params.userId === ctx.userId) throw selfRoleChange();

    const role = ctx.body.role;
    assertCanModify(db, ctx.role, target.role);
    assertCanAssign(db, ctx.role, role);

    db.transaction(() => {
      if (role !== 'owner') assertNotLastOwner(db, params.org, params.userId);
      db.prepare('UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?').run(role, params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.role_update', targetType: 'user', targetId: params.userId, result: 'allow', reasonCode: `${target.role}->${role}`, requestId: ctx.requestId });
    })();
    ok(res, { userId: params.userId, role, status: target.status });
  }, (p) => p.userId));

  // Suspend: reversible, but it is an account event, so live sessions end.
  router.post('/v1/orgs/:org/members/:userId/suspend', audited('member.suspend', 'user', (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');
    const target = findMember(db, params.org, params.userId);
    assertCanModify(db, ctx.role, target.role);
    if (target.status === 'suspended') return ok(res, { userId: params.userId, status: 'suspended' });

    db.transaction(() => {
      assertNotLastOwner(db, params.org, params.userId);
      db.prepare(`UPDATE memberships SET status = 'suspended' WHERE org_id = ? AND user_id = ?`).run(params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
      endActiveSessions(db, { orgId: params.org, userId: params.userId, reason: 'user_suspended' });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.suspend', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    })();
    ok(res, { userId: params.userId, status: 'suspended' });
  }, (p) => p.userId));

  router.delete('/v1/orgs/:org/members/:userId/suspend', audited('member.reinstate', 'user', (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');
    const target = findMember(db, params.org, params.userId);
    assertCanModify(db, ctx.role, target.role);

    db.transaction(() => {
      db.prepare(`UPDATE memberships SET status = 'active' WHERE org_id = ? AND user_id = ?`).run(params.org, params.userId);
      bumpPermVersion(db, { orgId: params.org, userId: params.userId });
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.reinstate', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    })();
    ok(res, { userId: params.userId, status: 'active' });
  }, (p) => p.userId));

  router.delete('/v1/orgs/:org/members/:userId', audited('member.remove', 'user', (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');
    const target = findMember(db, params.org, params.userId);
    if (params.userId === ctx.userId) throw forbidden('use leave to remove yourself', 'self_remove');
    assertCanModify(db, ctx.role, target.role);

    db.transaction(() => {
      assertNotLastOwner(db, params.org, params.userId);
      removeMembership(db, params.org, params.userId, 'membership_removed');
      audit(db, { orgId: params.org, actorId: ctx.userId, action: 'member.remove', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    })();
    ok(res, { userId: params.userId, status: 'removed' });
  }, (p) => p.userId));

  // --- effective permissions ---------------------------------------------------

  router.get('/v1/orgs/:org/users/:userId/effective', audited('permissions.read', 'user', (ctx, params, res) => {
    if (params.userId !== ctx.userId) assertCan(db, ctx, 'user:read');
    findMember(db, params.org, params.userId);

    const deviceId = ctx.query.get('deviceId');
    if (deviceId) {
      const device = db.prepare('SELECT 1 FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL').get(deviceId, params.org);
      if (!device) throw notFound();
    }
    const { role, permissions } = resolve(db, { userId: params.userId, orgId: params.org, deviceId });
    ok(res, { userId: params.userId, orgId: params.org, deviceId: deviceId ?? null, role, permissions });
  }, (p) => p.userId));

  // --- audit log -------------------------------------------------------------

  router.get('/v1/orgs/:org/audit', audited('audit.read', 'org', (ctx, params, res) => {
    assertCan(db, ctx, 'audit:read');
    const { limit, offset } = pageParams(ctx.query);
    const events = db.prepare(
      `SELECT a.id, a.actor_id, u.email AS actor_email, a.action, a.target_type, a.target_id,
              a.result, a.reason_code, a.request_id, a.at
         FROM audit_events a LEFT JOIN users u ON u.id = a.actor_id
        WHERE a.org_id = ?
        ORDER BY a.at DESC, a.id DESC
        LIMIT ? OFFSET ?`
    ).all(params.org, limit, offset);
    ok(res, { events, limit, offset });
  }, (p) => p.org));

}
