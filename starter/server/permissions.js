// The permission resolution engine. THE ONLY PLACE allow-vs-deny is decided.
//
// YOURS TO WRITE. This file ships as a stub.
//
// If you ever find yourself writing `if (role === 'admin')` outside this file — and
// especially under web/ — that is the bug this module exists to prevent. The console
// renders what this returns; it must never re-derive it.
//
// Inputs you will need:
//   permissions                 the catalogue (19 rows in db/reference.sql, but read it
//                               from the table, never hardcode it)
//   permission_patterns         the superset grants may name ('device:*', '*', ...)
//   role_permissions            the per-role baseline
//   memberships                 role + status + perm_version
//   grants / grant_permissions  per-user deltas, optionally device-scoped and windowed
//
// Behaviour to implement is in PERMISSIONS.md; the failure modes and the reason codes
// the API must report are in §10, and the shipped tests read those reason strings.
//
// NOTE: your database is personalised. There is at least one role and one permission in
// it that this exercise's prose never mentions. Read the tables; do not encode the
// documented matrix. Run `npm run personalisation` to see what you are dealing with.

const todo = (name) =>
  Object.assign(
    new Error(`TODO: server/permissions.js — ${name}() is yours to write (BRIEF.md §3).`),
    { code: 'NOT_IMPLEMENTED' }
  );

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

// Resolve one user's permission set in one org. deviceId === null means the org-level
// view; a deviceId means the exact per-device check.
export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const membership = db.prepare(`SELECT * FROM memberships
    WHERE user_id = ? AND org_id = ? LIMIT 1`).get(userId, orgId);

  if (!membership || membership.status !== 'active') {
    const permissions = db.prepare(`
    SELECT key FROM permissions
    ORDER BY key `).all();

    return { role: membership?.role ?? null, 
      permissions: Object.fromEntries(
      permissions.map(({ key }) => [
        key,
        {
          effect: 'deny',
          source: null,
          reason: membership ? 'suspended' : 'not_a_member'
        }
      ]))
    };
  }

  const permissions = db.prepare(`SELECT key FROM permissions ORDER BY key`).all().map(row => row.key);

  const rolePermissions = new Set(
    db.prepare(`SELECT permission FROM role_permissions WHERE role = ?`).all(membership.role).map(row => row.permission)
  );

  const nowIso = now instanceof Date ? now.toISOString() : new Date(now).toISOString();

  const grants = db.prepare(`
    SELECT g.id, g.device_id, g.effect, g.starts_at, g.expires_at, gp.permission
    FROM grants g
    JOIN grant_permissions gp ON gp.grant_id = g.id
    WHERE g.user_id = ? AND g.org_id = ? AND g.revoked_at IS NULL AND (g.starts_at IS NULL OR g.starts_at <= ?) AND (g.expires_at IS NULL OR ? < g.expires_at)
  `).all(userId, orgId, nowIso, nowIso);

  const matches = (pattern, permission) => pattern === '*' || pattern === permission || (pattern.endsWith(':*') && permission.startsWith(pattern.slice(0, -1)));

  const applicableGrants = (permission) =>
    grants.filter(grant => matches(grant.permission, permission)).filter(grant => grant.device_id === null || grant.device_id === deviceId);

  const resolved = {};

  for (const permission of permissions) {
    const applicable = applicableGrants(permission);

    const deny = applicable.find(grant => grant.effect === 'deny');

    if (deny) {
      resolved[permission] = {
        allowed: false,
        source: 'grant',
        reason: 'explicit_deny',
        grantId: deny.id
      };
      continue;
    }

    if (rolePermissions.has(permission)) {
      resolved[permission] = {
        allowed: true,
        source: 'role',
        reason: 'role'
      };
      continue;
    }

    const allow = applicable.find(grant => grant.effect === 'allow');

    if (allow) {
      resolved[permission] = {
        allowed: true,
        source: 'grant',
        reason: 'grant',
        grantId: allow.id
      };
      continue;
    }

    resolved[permission] = {
      allowed: false,
      source: null,
      reason: 'implicit'
    };
  }

  return {
    role: membership.role,
    permissions: Object.fromEntries(Object.entries(resolved).map(([permission, value]) => [
      permission, 
      { effect: value.allowed ? 'allow' : 'deny', 
        source: value.source, reason: value.reason,  
        ...(value.grantId ? { grantId: value.grantId } : {})
      }
    ]))
  };
}

// Batched form for list endpoints: { role, byDevice: { [deviceId]: permissions } }.
export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  throw todo('resolveDevices');
}

export function can(db, ctx, permission, deviceId) {
  const result = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId});

  return result.permissions[permission]?.effect === 'allow';
}

// Throws 403 carrying the reason code, so a refusal is debuggable.
export function assertCan(db, ctx, permission, deviceId) {
  throw todo('assertCan');
}

// No privilege laundering: you may only grant authority you hold at that scope.
export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  throw todo('assertMayGrant');
}

// The compound check: session:start AND the permission for the requested mode, and a
// refusal must distinguish WHICH of the two was missing.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const requiredPermission = MODE_PERMISSION[mode];

  if (!requiredPermission) {
    const error = new Error('invalid session mode');
    error.status = 400;
    error.reason = 'invalid_mode';
    throw error;
  }

  const sessionStart = can( db, ctx, 'session:start', deviceId);

  if (!sessionStart) {
    const error = new Error('missing session:start permission');
    error.status = 403;
    error.reason = 'missing_permission';
    throw error;
  }

  const devicePermission = can( db, ctx, requiredPermission, deviceId);

  if (!devicePermission) {
    const error = new Error(`missing ${requiredPermission} permission`);
    error.status = 403;
    error.reason = 'missing_device_permission';
    throw error;
  }

  return true;
}
