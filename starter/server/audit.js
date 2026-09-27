import { HttpError } from './http.js';
import { newId, nowIso } from './db.js';

export function audit(
  db,
  {
    orgId,
    actorId,
    action,
    targetType = null,
    targetId = null,
    result,
    reasonCode = null,
    requestId = null,
  }
) {
  if (!orgId) throw new Error('audit requires orgId');
  if (!action) throw new Error('audit requires action');

  if (result !== 'allow' && result !== 'deny') {
    throw new Error('audit result must be allow or deny');
  }

  db.prepare(`
    INSERT INTO audit_events (
      id,
      org_id,
      actor_id,
      action,
      target_type,
      target_id,
      result,
      reason_code,
      request_id,
      at
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    newId('audit'),
    orgId,
    actorId ?? null,
    action,
    targetType,
    targetId,
    result,
    reasonCode,
    requestId,
    nowIso()
  );
}

// Run fn(); if it refuses with a permission error,
// record the denial before rethrowing.
//
// Successful operations are NOT automatically logged here.
// The caller should write the allow row together with the mutation
// it describes, so one action produces exactly one audit row.
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof HttpError && err.status === 403) {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason ?? 'missing_permission',
        requestId: ctx.requestId ?? null,
      });
    }

    throw err;
  }
}