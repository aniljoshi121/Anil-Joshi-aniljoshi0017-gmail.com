// Invites: the only way to add a person to an org.
//
// The raw token is a bearer credential. It is returned once, stored only as a hash, and
// never logged. Single use is enforced by the partial unique index plus a guarded
// UPDATE, so two concurrent accepts cannot both win.

import { assertCan } from '../permissions.js';
import { assertCanAssign } from '../lifecycle.js';
import { audit } from '../audit.js';
import { newInviteToken, hashInviteToken, hashPassword, verifyPassword } from '../auth.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import { conflict, notFound, gone, unauthenticated, badRequest } from '../http.js';
import {
  audited, ok, created, normalizeEmail, requireString, sessionPayload, issueRefreshToken, setRefreshCookie,
} from './shared.js';

const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const isUniqueViolation = (err) => err?.code === 'SQLITE_CONSTRAINT_UNIQUE';

function inviteStatus(invite, now = nowIso()) {
  if (invite.accepted_at) return 'accepted';
  if (invite.revoked_at) return 'revoked';
  if (invite.expires_at <= now) return 'expired';
  return 'pending';
}

// Look up an invite by its raw token and refuse anything but a live one.
function liveInvite(db, rawToken) {
  const invite = db.prepare(
    `SELECT i.*, o.name AS org_name FROM invites i
       JOIN organizations o ON o.id = i.org_id AND o.deleted_at IS NULL
      WHERE i.token_hash = ?`
  ).get(hashInviteToken(String(rawToken)));
  if (!invite) throw notFound('invite not found');

  const status = inviteStatus(invite);
  if (status === 'accepted') throw conflict('invite has already been used');
  if (status !== 'pending') throw gone();
  return invite;
}

export function registerInviteRoutes(router, { db, secret }) {
  router.post('/v1/orgs/:org/invites', audited('invite.create', 'invite', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const email = normalizeEmail(ctx.body.email);
    const role = ctx.body.role;
    assertCanAssign(db, ctx.role, role);

    const member = db.prepare(
      `SELECT 1 FROM memberships m JOIN users u ON u.id = m.user_id
        WHERE m.org_id = ? AND u.email = ? AND m.status IN ('active', 'suspended')`
    ).get(params.org, email);
    if (member) throw conflict('that person is already a member');

    const raw = newInviteToken();
    const id = newId('inv');
    const expiresAt = new Date(Date.now() + INVITE_TTL_MS).toISOString();

    try {
      db.transaction(() => {
        db.prepare(
          `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
        ).run(id, params.org, email, role, hashInviteToken(raw), ctx.userId, expiresAt);
        audit(db, { orgId: params.org, actorId: ctx.userId, action: 'invite.create', targetType: 'invite', targetId: id, result: 'allow', requestId: ctx.requestId });
      })();
    } catch (err) {
      if (isUniqueViolation(err)) throw conflict('there is already a pending invite for that email');
      throw err;
    }

    created(res, { id, email, role, expiresAt, status: 'pending', inviteToken: raw });
  }));

  router.get('/v1/orgs/:org/invites', audited('invite.list', 'org', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const rows = db.prepare(
      `SELECT id, email, role, invited_by, expires_at, accepted_at, revoked_at, created_at
         FROM invites WHERE org_id = ? ORDER BY created_at DESC`
    ).all(params.org);
    const now = nowIso();
    ok(res, { invites: rows.map((i) => ({ ...i, status: inviteStatus(i, now) })) });
  }, (p) => p.org));

  router.delete('/v1/orgs/:org/invites/:id', audited('invite.revoke', 'invite', (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const changed = db.transaction(() => {
      const n = db.prepare(
        `UPDATE invites SET revoked_at = ? WHERE id = ? AND org_id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
      ).run(nowIso(), params.id, params.org).changes;
      if (n) audit(db, { orgId: params.org, actorId: ctx.userId, action: 'invite.revoke', targetType: 'invite', targetId: params.id, result: 'allow', requestId: ctx.requestId });
      return n;
    })();
    if (!changed) throw notFound();
    ok(res, { id: params.id, status: 'revoked' });
  }, (p) => p.id));

  // Public peek: just enough to render "you've been invited to X as Y". No org id, no
  // member list, no device data.
  router.get('/v1/invites/:token', (ctx, params, res) => {
    const invite = liveInvite(db, params.token);
    ok(res, { orgName: invite.org_name, role: invite.role, email: invite.email, expiresAt: invite.expires_at });
  });

  // Public accept. One transaction: find or create the user, activate the membership,
  // consume the invite. An existing account has to prove it owns the email by password.
  router.post('/v1/invites/:token/accept', (ctx, params, res) => {
    const password = typeof ctx.body.password === 'string' ? ctx.body.password : '';

    const { userId, orgId, role } = db.transaction(() => {
      const invite = liveInvite(db, params.token);
      const now = nowIso();

      let user = db.prepare('SELECT id, password_hash FROM users WHERE email = ?').get(invite.email);
      if (user) {
        if (!verifyPassword(password, user.password_hash)) throw unauthenticated('invalid email or password');
      } else {
        const name = requireString(ctx.body.name, 'name');
        if (password.length < 8) throw badRequest('password must be at least 8 characters');
        user = { id: newId('usr') };
        db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
          .run(user.id, invite.email, name, hashPassword(password));
      }

      const consumed = db.prepare(
        `UPDATE invites SET accepted_at = ?, accepted_by = ?
          WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL`
      ).run(now, user.id, invite.id).changes;
      if (!consumed) throw conflict('invite has already been used');

      const existing = db.prepare('SELECT status FROM memberships WHERE org_id = ? AND user_id = ?').get(invite.org_id, user.id);
      if (existing && existing.status !== 'removed' && existing.status !== 'invited') {
        throw conflict('you are already a member of this organization');
      }
      if (existing) {
        db.prepare(
          `UPDATE memberships SET role = ?, status = 'active', invited_by = ?, joined_at = ? WHERE org_id = ? AND user_id = ?`
        ).run(invite.role, invite.invited_by, now, invite.org_id, user.id);
        bumpPermVersion(db, { orgId: invite.org_id, userId: user.id });
      } else {
        db.prepare(
          `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?, ?, ?, ?, 'active', ?, ?)`
        ).run(newId('mem'), invite.org_id, user.id, invite.role, invite.invited_by, now);
      }

      audit(db, { orgId: invite.org_id, actorId: user.id, action: 'invite.accept', targetType: 'invite', targetId: invite.id, result: 'allow' });
      return { userId: user.id, orgId: invite.org_id, role: invite.role };
    })();

    setRefreshCookie(res, issueRefreshToken(db, userId));
    ok(res, { ...sessionPayload(db, secret, userId, orgId), role });
  });
}
