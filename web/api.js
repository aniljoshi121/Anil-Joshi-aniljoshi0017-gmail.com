// The API client. The access token lives in this closure only: never in
// localStorage, sessionStorage or a cookie the page can read. The refresh token is an
// httpOnly cookie the browser sends to /v1/auth on its own.

export class ApiError extends Error {
  constructor(status, code, message, reason) {
    super(message);
    this.status = status;
    this.code = code;
    this.reason = reason;
  }
}

export function createApi({ onSession, onSignedOut }) {
  let token = null;
  let orgId = null;

  async function raw(method, path, body, bearer = token) {
    const headers = {};
    if (bearer) headers.authorization = `Bearer ${bearer}`;
    if (body !== undefined) headers['content-type'] = 'application/json';

    let res;
    try {
      res = await fetch(`/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
      throw new ApiError(0, 'NETWORK', 'Cannot reach the server. Check that it is running, then try again.', null);
    }

    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* not JSON */ }

    if (!res.ok) {
      const e = json?.error;
      throw new ApiError(res.status, e?.code ?? 'INTERNAL', e?.message ?? `The server answered ${res.status}.`, e?.reason ?? null);
    }
    return json;
  }

  function adopt(payload) {
    token = payload.token;
    orgId = payload.orgId;
    onSession(payload);
    return payload;
  }

  // Use the refresh cookie to get a new access token, staying in the current org
  // when possible.
  async function refresh() {
    try {
      return adopt(await raw('POST', '/auth/refresh', orgId ? { orgId } : {}, null));
    } catch (err) {
      if (err.status === 404 && orgId) {
        orgId = null;
        return adopt(await raw('POST', '/auth/refresh', {}, null));
      }
      throw err;
    }
  }

  // Authenticated request. A stale or expired token is refreshed once and retried;
  // if that fails too, the user is signed out with the reason.
  async function request(method, path, body) {
    try {
      return await raw(method, path, body);
    } catch (err) {
      if (err.status !== 401 || !token) throw err;
      try {
        await refresh();
      } catch {
        token = null;
        onSignedOut('Your sign-in has ended. Sign in again to continue.');
        throw err;
      }
      return raw(method, path, body);
    }
  }

  return {
    get: (path) => request('GET', path),
    post: (path, body = {}) => request('POST', path, body),
    patch: (path, body = {}) => request('PATCH', path, body),
    del: (path) => request('DELETE', path),

    login: async (email, password) => adopt(await raw('POST', '/auth/login', { email, password }, null)),
    resume: refresh,
    switchOrg: async (nextOrgId) => adopt(await request('POST', '/auth/token', { orgId: nextOrgId })),
    logout: async () => {
      try { await raw('POST', '/auth/logout', {}); } catch { /* signing out anyway */ }
      token = null;
      orgId = null;
    },

    // Public invite endpoints: no bearer token.
    peekInvite: (inviteToken) => raw('GET', `/invites/${encodeURIComponent(inviteToken)}`, undefined, null),
    acceptInvite: (inviteToken, body) => raw('POST', `/invites/${encodeURIComponent(inviteToken)}/accept`, body, null),
  };
}
