import { issueAccessToken, verifyPassword, hashPassword, newInviteToken, hashInviteToken } from '../auth.js';
import { send, badRequest, unauthenticated, notFound, HttpError, selfRoleChange } from '../http.js';
import { assertCanStartSession, resolveDevices, assertCan } from '../permissions.js';
import { nowIso, newId } from '../db.js';
import { audit } from '../audit.js';
import { changeMemberRole } from '../membership.js';

export function registerRoutes(router, deps) {
  const { db, secret } = deps;

  router.post('/v1/auth/login', (ctx, params, res) => {
    const { email, password } = ctx.body;

    if (typeof email !== 'string' || typeof password !== 'string' || email.trim() === '' || password === '') {
      throw badRequest('email and password are required');
    }

    const normalizedEmail = email.trim().toLowerCase();

    const user = db.prepare(`SELECT * FROM users WHERE email = ? LIMIT 1`).get(normalizedEmail);

    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated('invalid credentials');
    }

    const memberships = db.prepare(`
      SELECT m.id, m.org_id, m.role, m.status, m.perm_version, o.name AS org_name, o.theme
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL
      ORDER BY o.name
    `).all(user.id);

    if (memberships.length === 0) {
      throw unauthenticated('not a member of any organization');
    }

    const orgs = memberships.map((membership) => ({
      id: membership.org_id,
      name: membership.org_name,
      role: membership.role,
      theme: membership.theme,
    }));

    const membership = memberships[0];

    const accessToken = issueAccessToken(
      { userId: user.id, orgId: membership.org_id, role: membership.role, permVersion: membership.perm_version, }, secret
    );

    send(res, 200, {
      token: accessToken,
      user: {
        id: user.id, email: user.email, name: user.name,
      },
      role: membership.role, orgs,
    });
  });

  router.post('/v1/auth/token', (ctx, params, res) => {
    const { orgId } = ctx.body;

    if (typeof orgId !== 'string' || orgId.length === 0) {
      throw badRequest('orgId is required');
    }

    const membership = db.prepare(`
      SELECT
        m.id,
        m.org_id,
        m.role,
        m.status,
        m.perm_version,
        o.name AS org_name,
        o.theme
      FROM memberships m
      JOIN organizations o ON o.id = m.org_id
      WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'active'
        AND o.deleted_at IS NULL
      LIMIT 1
    `).get(ctx.userId, orgId);

    if (!membership) {
      throw notFound();
    }

    const accessToken = issueAccessToken(
      {
        userId: ctx.userId,
        orgId: membership.org_id,
        role: membership.role,
        permVersion: membership.perm_version,
      },
      secret
    );

    send(res, 200, {
      token: accessToken,
      role: membership.role,
      org: {
        id: membership.org_id,
        name: membership.org_name,
        theme: membership.theme,
      },
    });
  });

  router.get('/v1/orgs/:orgId/devices', (ctx, params, res) => {
    const orgId = params.orgId;

    if (orgId !== ctx.orgId) {
      throw notFound();
    }

    assertCan(db, ctx, 'device:list');

    const devices = db.prepare(`
      SELECT id, name, kind, online, created_at
      FROM devices
      WHERE org_id = ?
        AND deleted_at IS NULL
      ORDER BY name
    `).all(orgId);

    const visibleDeviceIds = [];

    for (const device of devices) {
      const permissions = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: [device.id], }).byDevice[device.id];

      if (permissions['device:view']?.effect === 'allow') {
        visibleDeviceIds.push({ ...device, permissions, });
      }
    }

    send(res, 200, { devices: visibleDeviceIds, });
  });

  router.post('/v1/orgs', (ctx, params, res) => {
    const { name } = ctx.body;

    if (typeof name !== 'string' || name.trim() === '') {
      throw badRequest('name is required');
    }

    const orgId = newId('org');
    const membershipId = newId('mem');

    const theme = 'default';

    const create = db.transaction(() => {
      db.prepare(`
      INSERT INTO organizations
        (id, name, theme, max_session_minutes)
      VALUES (?, ?, ?, ?)
    `).run(
        orgId,
        name.trim(),
        theme,
        60
      );

      db.prepare(`
      INSERT INTO memberships
        (id, org_id, user_id, role, status, perm_version, joined_at)
      VALUES (?, ?, ?, 'owner', 'active', 1, ?)
    `).run(
        membershipId,
        orgId,
        ctx.userId,
        nowIso()
      );
    });

    create();

    send(res, 201, {
      id: orgId,
      name: name.trim(),
      theme,
      role: 'owner',
    });
  });

  router.get('/v1/orgs/:orgId/audit', (ctx, params, res) => {
    const { orgId } = params;

    if (orgId !== ctx.orgId) {
      throw notFound();
    }

    assertCan(db, ctx, 'audit:read');

    const rawLimit = ctx.query?.get('limit');
    const rawOffset = ctx.query?.get('offset');

    const limit = rawLimit === null ? 50 : Number(rawLimit);
    const offset = rawOffset === null ? 0 : Number(rawOffset);

    if (!Number.isInteger(limit) || limit <= 0 || limit > 1000) {
      throw badRequest('limit must be an integer between 1 and 1000');
    }

    if (!Number.isInteger(offset) || offset < 0) {
      throw badRequest('offset must be a non-negative integer');
    }

    const events = db.prepare(`SELECT id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT ? OFFSET ?`).all(orgId, limit, offset);

    send(res, 200, {events, limit, offset});
  });

  router.post('/v1/orgs/:orgId/invites', (ctx, params, res) => {
  const { orgId } = params;

  if (orgId !== ctx.orgId) {
    throw notFound();
  }

  assertCan(db, ctx, 'user:invite');

  const { email, role } = ctx.body;

  if (typeof email !== 'string' || email.trim() === '') {
    throw badRequest('email is required');
  }

  if (typeof role !== 'string' || role.trim() === '') {
    throw badRequest('role is required');
  }

  const normalizedEmail = email.trim().toLowerCase();
  const normalizedRole = role.trim();

  const validRole = db.prepare(`
    SELECT key
    FROM roles
    WHERE key = ?
    LIMIT 1
  `).get(normalizedRole);

  if (!validRole) {
    throw badRequest('invalid role');
  }

  const existingUser = db.prepare(`
    SELECT id
    FROM users
    WHERE email = ?
    LIMIT 1
  `).get(normalizedEmail);

  if (existingUser) {
    throw new HttpError(
      409,
      'CONFLICT',
      'a user with this email already exists'
    );
  }

  const rawToken = newInviteToken();
  const tokenHash = hashInviteToken(rawToken);

  const inviteId = newId('invite');

  // Keep invite lifetime deterministic and short.
  const expiresAt = new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000
  ).toISOString();

  try {
    db.prepare(`
      INSERT INTO invites (
        id,
        org_id,
        email,
        role,
        token_hash,
        invited_by,
        expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      inviteId,
      orgId,
      normalizedEmail,
      normalizedRole,
      tokenHash,
      ctx.userId,
      expiresAt
    );
  } catch (err) {
    if (err?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      throw new HttpError(
        409,
        'CONFLICT',
        'there is already a live invite for this email'
      );
    }

    throw err;
  }

  send(res, 201, {
    inviteToken: rawToken,
    invite: {
      id: inviteId,
      email: normalizedEmail,
      role: normalizedRole,
      expiresAt,
    },
  });
});

router.get('/v1/invites/:token', (ctx, params, res) => {
  const rawToken = params.token;

  if (typeof rawToken !== 'string' || rawToken.length === 0) {
    throw notFound();
  }

  const tokenHash = hashInviteToken(rawToken);

  const invite = db.prepare(`
    SELECT
      i.id,
      i.email,
      i.role,
      i.expires_at,
      i.accepted_at,
      i.revoked_at,
      o.name AS org_name
    FROM invites i
    JOIN organizations o ON o.id = i.org_id
    WHERE i.token_hash = ?
      AND o.deleted_at IS NULL
    LIMIT 1
  `).get(tokenHash);

  if (!invite) {
    throw notFound();
  }

  if (invite.accepted_at || invite.revoked_at) {
    throw notFound();
  }

  if (new Date(invite.expires_at).getTime() <= Date.now()) {
    throw notFound();
  }

  send(res, 200, {
    email: invite.email,
    role: invite.role,
    orgName: invite.org_name,
    expiresAt: invite.expires_at,
  });
});

router.post('/v1/invites/:token/accept', (ctx, params, res) => {
  const rawToken = params.token;

  if (typeof rawToken !== 'string' || rawToken.length === 0) {
    throw notFound();
  }

  const { name, password } = ctx.body;

  if (typeof name !== 'string' || name.trim() === '') {
    throw badRequest('name is required');
  }

  if (typeof password !== 'string' || password.length < 8) {
    throw badRequest('password must be at least 8 characters');
  }

  const tokenHash = hashInviteToken(rawToken);

  const invite = db.prepare(`
    SELECT *
    FROM invites
    WHERE token_hash = ?
    LIMIT 1
  `).get(tokenHash);

  if (!invite) {
    throw notFound();
  }

  if (invite.accepted_at || invite.revoked_at) {
    throw new HttpError(
      409,
      'CONFLICT',
      'invite has already been used'
    );
  }

  if (new Date(invite.expires_at).getTime() <= Date.now()) {
    throw new HttpError(
      410,
      'GONE',
      'invite has expired'
    );
  }

  const existingUser = db.prepare(`
    SELECT id
    FROM users
    WHERE email = ?
    LIMIT 1
  `).get(invite.email);

  if (existingUser) {
    throw new HttpError(
      409,
      'CONFLICT',
      'a user with this email already exists'
    );
  }

  const userId = newId('usr');
  const membershipId = newId('mem');
  const passwordHash = hashPassword(password);

  const accept = db.transaction(() => {
    db.prepare(`
      INSERT INTO users (
        id,
        email,
        name,
        password_hash
      )
      VALUES (?, ?, ?, ?)
    `).run(
      userId,
      invite.email,
      name.trim(),
      passwordHash
    );

    db.prepare(`
      INSERT INTO memberships (
        id,
        org_id,
        user_id,
        role,
        status,
        perm_version,
        invited_by,
        joined_at
      )
      VALUES (?, ?, ?, ?, 'active', 1, ?, ?)
    `).run(
      membershipId,
      invite.org_id,
      userId,
      invite.role,
      invite.invited_by,
      nowIso()
    );

    db.prepare(`
      UPDATE invites
      SET accepted_at = ?,
          accepted_by = ?
      WHERE id = ?
    `).run(
      nowIso(),
      userId,
      invite.id
    );
  });

  try {
    accept();
  } catch (err) {
    if (err?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      throw new HttpError(
        409,
        'CONFLICT',
        'invite has already been used'
      );
    }

    throw err;
  }

  send(res, 200, {
    user: {
      id: userId,
      email: invite.email,
      name: name.trim(),
    },
    role: invite.role,
    orgId: invite.org_id,
  });
});

  router.patch('/v1/orgs/:orgId/members/:userId', (ctx, params, res) => {
    const { orgId, userId } = params;

    if (orgId !== ctx.orgId) {
      throw notFound();
    }

    // The actor needs the explicit role-management permission.
    assertCan(db, ctx, 'user:role:update');

    const { role } = ctx.body;

    if (typeof role !== 'string' || role.trim() === '') {
      throw badRequest('role is required');
    }

    const membership = changeMemberRole(
      db,
      ctx,
      userId,
      role.trim()
    );

    send(res, 200, {
      membership
    });
  });

  router.delete('/v1/orgs/:orgId/members/me', (ctx, params, res) => {
    const { orgId } = params;

    if (orgId !== ctx.orgId) {
      throw notFound();
    }

    const membership = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? LIMIT 1`).get(orgId, ctx.userId);

    if (!membership) {
      throw notFound();
    }

    if (membership.role === 'owner') {
      const owners = db.prepare(`SELECT COUNT(*) AS count FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active'`).get(orgId);

      if (owners.count <= 1) {
        throw new HttpError(409, 'LAST_OWNER', 'the org must always have at least one owner');
      }
    }

    db.prepare(`UPDATE memberships
    SET status = 'removed', perm_version = perm_version + 1
    WHERE org_id = ? AND user_id = ?`).run(orgId, ctx.userId);

    db.prepare(`UPDATE sessions SET state = 'ended', ended_at = ?, end_reason = 'membership_removed' WHERE org_id = ? AND user_id = ? AND state = 'active'`).run(nowIso(), orgId, ctx.userId);

    send(res, 200, { ok: true });
  });

  router.post('/v1/orgs/:orgId/grants', (ctx, params, res) => {
    const { orgId } = params;

    if (orgId !== ctx.orgId) {
      throw notFound();
    }

    assertCan(db, ctx, 'grant:create');

    const { userId, deviceId = null, effect, permissions, startsAt = null, expiresAt = null,} = ctx.body;

    if (typeof userId !== 'string' || userId.trim() === '') {
      throw badRequest('userId is required');
    }

    if (!['allow', 'deny'].includes(effect)) {
      throw badRequest('effect must be allow or deny');
    }

    if (!Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest(
        'permissions must contain at least one permission'
      );
    }

    if (permissions.some((p) => typeof p !== 'string' || p.trim() === '')) {
      throw badRequest('permissions must contain valid strings');
    }

    const target = db.prepare(`SELECT id, role, status FROM memberships WHERE org_id = ? AND user_id = ? LIMIT 1`).get(orgId, userId);

    if (!target) {
      throw notFound();
    }

    if (userId === ctx.userId) {
      throw new HttpError(403, 'FORBIDDEN', 'you cannot grant permissions to yourself', 'self_grant');
    }

    if (deviceId !== null) {
      const device = db.prepare(`
      SELECT id FROM devices
      WHERE id = ? AND org_id = ? AND deleted_at IS NULL LIMIT 1
    `).get(deviceId, orgId);

      if (!device) {
        throw notFound();
      }
    }

    const normalizedPermissions = [...new Set(
      permissions.map((p) => p.trim())
    )];

    const valid = db.prepare(`SELECT pattern FROM permission_patterns WHERE pattern = ?`);

    for (const permission of normalizedPermissions) {
      if (!valid.get(permission)) {
        throw new HttpError(400, 'VALIDATION', `unknown permission: ${permission}`, 'unknown_permission');
      }
    }

    const grantId = newId('grant');

    const create = db.transaction(() => {
      db.prepare(`INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(grantId, orgId, userId, deviceId, effect, startsAt, expiresAt, ctx.userId);

    const insertPermission = db.prepare(`
      INSERT INTO grant_permissions (grant_id, permission)
      VALUES (?, ?)
    `);

      for (const permission of normalizedPermissions) {
        insertPermission.run(grantId, permission);
      }

      db.prepare(`UPDATE memberships
      SET perm_version = perm_version + 1
      WHERE org_id = ? AND user_id = ?`).run(orgId, userId);
    });

    create();

    const grant = db.prepare(`SELECT * FROM grants WHERE id = ?`).get(grantId);

    send(res, 201, {
      grant: {...grant, permissions: normalizedPermissions},
    });
  });

  router.post('/v1/orgs/:orgId/sessions', (ctx, params, res) => {
    const { orgId } = params;

    if (orgId !== ctx.orgId) {
      throw notFound();
    }

    const { deviceId, mode } = ctx.body;

    if (typeof deviceId !== 'string' || typeof mode !== 'string') {
      throw badRequest('deviceId and mode are required');
    }

    if (!['view', 'control', 'terminal'].includes(mode)) {
      throw badRequest('invalid session mode');
    }

    const device = db.prepare(`
      SELECT * FROM devices
      WHERE id = ? AND org_id = ? AND deleted_at IS NULL
      LIMIT 1
    `).get(deviceId, orgId);

    if (!device) {
      throw notFound();
    }

    assertCanStartSession(db, ctx, mode, deviceId);

    const now = nowIso();

    const org = db.prepare(`
      SELECT max_session_minutes
      FROM organizations
      WHERE id = ? AND deleted_at IS NULL LIMIT 1
    `).get(orgId);

    if (!org) {
      throw notFound();
    }

    const expiresAt = new Date(Date.now() + org.max_session_minutes * 60 * 1000).toISOString();

    const sessionId = newId('sess');

    const resolved = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: [deviceId], }).byDevice[deviceId];

    const authorizedBy = JSON.stringify({ role: ctx.role, permissions: resolved, userId: ctx.userId, orgId: ctx.orgId, deviceId, mode, at: now, });

    try {
      db.prepare(`
        INSERT INTO sessions ( id, org_id, user_id, device_id, mode, state, authorized_by, started_at, expires_at) 
        VALUES
        (?, ?, ?, ?, ?, 'active', ?, ?, ?)
      `).run(sessionId, orgId, ctx.userId, deviceId, mode, authorizedBy, now, expiresAt);
    } catch (err) {
      if (err?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        const holder = db.prepare(`SELECT id FROM sessions
          WHERE device_id = ? AND state = 'active' AND mode IN ('control', 'terminal')
          LIMIT 1
        `).get(deviceId);

        throw new HttpError(409, 'DEVICE_BUSY',
          holder ? `device already has an exclusive session (${holder.id})` : 'device already has an exclusive session'
        );
      }

      throw err;
    }

    const session = db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(sessionId);

    send(res, 201, { session, });
  });

  router.get('/v1/orgs/:orgId/sessions', (ctx, params, res) => {
    const { orgId } = params;

    if (orgId !== ctx.orgId) {
      throw notFound();
    }

    const sessions = db.prepare(`
      SELECT * FROM sessions
      WHERE org_id = ?
      ORDER BY started_at DESC
    `).all(orgId);

    send(res, 200, { sessions, });
  });

  router.get('/v1/sessions/:sessionId', (ctx, params, res) => {
    const session = db.prepare(`
      SELECT * FROM sessions
      WHERE id = ? AND org_id = ?
      LIMIT 1
    `).get(params.sessionId, ctx.orgId);

    if (!session) {
      throw notFound();
    }

    send(res, 200, session);
  });

  router.post('/v1/orgs/:orgId/members/:userId/suspend', (ctx, params, res) => {
    const { orgId, userId } = params;

    if (orgId !== ctx.orgId) {
      throw notFound();
    }

    assertCan(db, ctx, 'user:role:update');

    if (userId === ctx.userId) {
      throw selfRoleChange();
    }

    const membership = db.prepare(`
    SELECT *
    FROM memberships
    WHERE org_id = ?
      AND user_id = ?
    LIMIT 1
  `).get(orgId, userId);

    if (!membership) {
      throw notFound();
    }

    db.prepare(`
    UPDATE memberships
    SET status = 'suspended',
        perm_version = perm_version + 1
    WHERE org_id = ?
      AND user_id = ?
  `).run(orgId, userId);

    db.prepare(`
    UPDATE sessions
    SET state = 'ended',
        ended_at = ?,
        end_reason = 'user_suspended'
    WHERE org_id = ?
      AND user_id = ?
      AND state = 'active'
  `).run(nowIso(), orgId, userId);

    send(res, 200, {
      ok: true
    });
  });

  router.delete('/v1/orgs/:orgId/members/:userId/suspend', (ctx, params, res) => {
    const { orgId, userId } = params;

    if (orgId !== ctx.orgId) {
      throw notFound();
    }

    assertCan(db, ctx, 'user:role:update');

    const membership = db.prepare(`
    SELECT *
    FROM memberships
    WHERE org_id = ?
      AND user_id = ?
    LIMIT 1
  `).get(orgId, userId);

    if (!membership) {
      throw notFound();
    }

    db.prepare(`
    UPDATE memberships
    SET status = 'active',
        perm_version = perm_version + 1
    WHERE org_id = ?
      AND user_id = ?
  `).run(orgId, userId);

    send(res, 200, {
      ok: true
    });
  });
}