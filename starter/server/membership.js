import { forbidden, lastOwner, selfRoleChange, notFound } from './http.js';

const ROLE_RANK = {
  viewer: 1,
  auditor: 2,
  operator: 3,
  admin: 4,
  owner: 5,
};

export function changeMemberRole(db, ctx, targetUserId, nextRole) {
  if (targetUserId === ctx.userId) {
    throw selfRoleChange();
  }

  if (!ROLE_RANK[nextRole]) {
    throw forbidden('invalid target role');
  }

  const target = db.prepare(`
    SELECT
      m.id,
      m.user_id,
      m.org_id,
      m.role,
      m.status,
      m.perm_version,
      u.email,
      u.name
    FROM memberships m
    JOIN users u ON u.id = m.user_id
    WHERE m.org_id = ?
      AND m.user_id = ?
    LIMIT 1
  `).get(ctx.orgId, targetUserId);

  if (!target) {
    throw notFound();
  }

  const actorRank = ROLE_RANK[ctx.role];
  const targetRank = ROLE_RANK[target.role];

  if (!actorRank || !targetRank) {
    throw forbidden('invalid role');
  }

  /*
   * Owners are allowed to demote another owner as long as
   * at least one other active owner remains.
   */
  if (ctx.role === 'owner' && target.role === 'owner' && nextRole !== 'owner') {
    const owners = db.prepare(`
      SELECT COUNT(*) AS count
      FROM memberships
      WHERE org_id = ?
        AND role = 'owner'
        AND status = 'active'
    `).get(ctx.orgId);

    if (owners.count <= 1) {
      throw lastOwner();
    }

    db.prepare(`
      UPDATE memberships
      SET role = ?,
          perm_version = perm_version + 1
      WHERE org_id = ?
        AND user_id = ?
    `).run(nextRole, ctx.orgId, targetUserId);

    return db.prepare(`
      SELECT
        m.id,
        m.user_id,
        m.org_id,
        m.role,
        m.status,
        m.perm_version,
        u.email,
        u.name
      FROM memberships m
      JOIN users u ON u.id = m.user_id
      WHERE m.org_id = ?
        AND m.user_id = ?
      LIMIT 1
    `).get(ctx.orgId, targetUserId);
  }

  /*
   * Normal modification hierarchy.
   * Equal or higher roles cannot be modified.
   */
  if (targetRank >= actorRank) {
    throw forbidden('cannot modify an equal or higher role');
  }

  /*
   * Only an owner can confer ownership.
   */
  if (nextRole === 'owner' && ctx.role !== 'owner') {
    throw forbidden('only an owner can assign owner');
  }

  db.prepare(`
    UPDATE memberships
    SET role = ?,
        perm_version = perm_version + 1
    WHERE org_id = ?
      AND user_id = ?
  `).run(nextRole, ctx.orgId, targetUserId);

  return db.prepare(`
    SELECT
      m.id,
      m.user_id,
      m.org_id,
      m.role,
      m.status,
      m.perm_version,
      u.email,
      u.name
    FROM memberships m
    JOIN users u ON u.id = m.user_id
    WHERE m.org_id = ?
      AND m.user_id = ?
    LIMIT 1
  `).get(ctx.orgId, targetUserId);
}