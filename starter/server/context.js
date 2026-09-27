import { verifyAccessToken, assertFresh } from './auth.js';
import { notFound, unauthenticated } from './http.js';

export function authenticate(db, secret) {
  return function buildContext(req, params) {
    const authorization = req.headers.authorization;

    if (typeof authorization !== 'string') {
      throw unauthenticated();
    }

    const match = /^Bearer\s+(.+)$/i.exec(authorization);

    if (!match) {
      throw unauthenticated();
    }

    const token = match[1].trim();

    if (!token) {
      throw unauthenticated();
    }

    const claims = verifyAccessToken(token, secret);

    const userId = claims.sub;
    const orgId = claims.org;

    if (typeof userId !== 'string' || userId.length === 0 || typeof orgId !== 'string' || orgId.length === 0) {
      throw unauthenticated('invalid access token');
    }

    const requestedOrgId = params?.orgId ?? params?.organizationId ?? params?.org;

    if (requestedOrgId !== undefined && requestedOrgId !== orgId) {
      throw notFound();
    }

    const membership = db.prepare(`
      SELECT * FROM memberships
      WHERE user_id = ? AND org_id = ? LIMIT 1
    `).get(userId, orgId);

    if (!membership || membership.status !== 'active') {
      throw unauthenticated('not a member of this org');
    }

    assertFresh(claims, membership);

    return { userId, orgId, role: membership.role, membership, claims};
  };
}