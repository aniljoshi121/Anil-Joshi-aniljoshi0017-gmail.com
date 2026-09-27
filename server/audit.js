// Append-only audit writes. audit_events has triggers that refuse UPDATE and DELETE,
// so this module only ever INSERTs.
//
// Success rows are written by the route, inside the same transaction as the change.
// Denied attempts are written here, by auditDenials, so every refusal leaves a trace.

import { HttpError } from './http.js';
import { newId, nowIso } from './db.js';

export function audit(db, { orgId, actorId, action, targetType = null, targetId = null, result, reasonCode = null, requestId = null }) {
  db.prepare(
    `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(newId('aud'), orgId, actorId, action, targetType, targetId, result, reasonCode, requestId, nowIso());
}

// Refusals worth recording: permission denials and the guard rails around them.
const DENIAL_CODES = new Set(['FORBIDDEN', 'SELF_ROLE_CHANGE', 'LAST_OWNER']);

// Run fn(); if it refuses with a permission error, record the denial before rethrowing.
export async function auditDenials(db, ctx, meta, fn) {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof HttpError && DENIAL_CODES.has(err.code) && ctx.orgId) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason ?? err.code.toLowerCase(),
        requestId: ctx.requestId,
      });
    }
    throw err;
  }
}
