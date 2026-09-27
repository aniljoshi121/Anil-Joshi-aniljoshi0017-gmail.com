import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createApi } from './api.js';
import { allowed, Notice, useNotice } from './ui.jsx';
import Devices from './views/Devices.jsx';
import People from './views/People.jsx';
import Grants from './views/Grants.jsx';
import Sessions from './views/Sessions.jsx';
import Audit from './views/Audit.jsx';
import Admin from './views/Admin.jsx';

// The cards and the permission that puts each one on screen (UI-INVENTORY.md §2).
// These are gates on the server's resolved answer, not a role table: the console
// never knows which roles hold which permissions.
const CARDS = [
  { key: 'devices', label: 'Devices', show: (p) => allowed(p, 'device:list'), View: Devices },
  { key: 'people', label: 'People', show: (p) => allowed(p, 'user:read'), View: People },
  { key: 'grants', label: 'Grants', show: (p) => allowed(p, 'user:read'), View: Grants },
  { key: 'sessions', label: 'Sessions', show: (p) => allowed(p, 'session:view'), View: Sessions },
  { key: 'audit', label: 'Audit', show: (p) => allowed(p, 'audit:read'), View: Audit },
  { key: 'admin', label: 'Settings', show: (p) => allowed(p, 'org:update') || allowed(p, 'org:delete'), View: Admin },
];

export default function App() {
  const [session, setSession] = useState(null);
  const [booting, setBooting] = useState(true);
  const [signedOutReason, setSignedOutReason] = useState(null);

  const api = useMemo(() => createApi({
    onSession: (payload) => setSession(payload),
    onSignedOut: (reason) => { setSession(null); setSignedOutReason(reason); },
  }), []);

  const inviteToken = window.location.pathname.match(/^\/invite\/([^/]+)/)?.[1];

  // On load, try the refresh cookie so a reload keeps you signed in.
  useEffect(() => {
    if (inviteToken) { setBooting(false); return; }
    api.resume().catch(() => {}).finally(() => setBooting(false));
  }, []);

  if (inviteToken) return <InvitePage api={api} token={decodeURIComponent(inviteToken)} />;
  if (booting) return <div className="boot" aria-busy="true">Loading RemoteOps…</div>;
  if (!session) return <Login api={api} notice={signedOutReason} />;
  return <Console api={api} session={session} onSignOut={async () => { await api.logout(); setSession(null); setSignedOutReason(null); }} />;
}

// --- sign in ------------------------------------------------------------------

function Login({ api, notice, banner }) {
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const email = String(form.get('email') ?? '').trim();
    const password = String(form.get('password') ?? '');
    setError(null);

    if (!email || !password) {
      setError({ code: 'VALIDATION', text: !email && !password ? 'Enter your email and password.' : !email ? 'Enter your email address.' : 'Enter your password.' });
      return;
    }
    setBusy(true);
    try {
      await api.login(email, password);
    } catch (err) {
      // Show the server's answer as it is. It is the same for an unknown account and a
      // wrong password, and the screen must not be more specific than that.
      const text = err.code === 'UNAUTHENTICATED' ? `Sign-in failed: ${err.message}.` : err.message;
      setError({ code: err.code, text });
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="login">
      <div className="login-mark" aria-hidden="true"><span /><span /><span /></div>
      <h1>RemoteOps</h1>
      <p className="muted">Who can reach which machine, in which organization.</p>
      {banner && <p className="notice notice-ok" role="status">{banner}</p>}
      {notice && <p className="notice notice-ok" role="status">{notice}</p>}
      <form data-testid="login-form" onSubmit={submit} noValidate>
        <label>Email <input data-testid="login-email" name="email" type="email" autoComplete="username" autoFocus /></label>
        <label>Password <input data-testid="login-password" name="password" type="password" autoComplete="current-password" /></label>
        {error && (
          <p className="notice notice-error" data-testid="login-error" data-error-code={error.code} role="alert" aria-live="assertive">
            {error.text}
          </p>
        )}
        <button type="submit" className="primary" data-testid="login-submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      </form>
    </main>
  );
}

// --- the signed-in console ----------------------------------------------------

function Console({ api, session, onSignOut }) {
  const cards = CARDS.filter((c) => c.show(session.permissions));
  const [active, setActive] = useState(cards[0]?.key ?? null);
  const [switching, setSwitching] = useState(false);
  const { notice, fail, clear } = useNotice();
  const org = session.orgs.find((o) => o.id === session.orgId);
  const mainRef = useRef(null);

  // If the current card disappears (permissions changed, or a new org), fall back to
  // the first card this person can see here.
  useEffect(() => {
    if (!cards.some((c) => c.key === active)) setActive(cards[0]?.key ?? null);
  }, [session.orgId, session.permissions]);

  const switchTo = async (orgId) => {
    if (orgId === session.orgId) return;
    setSwitching(true);
    clear();
    try {
      const next = await api.switchOrg(orgId);
      setActive(CARDS.find((c) => c.show(next.permissions))?.key ?? null);
    } catch (e) { fail(e, 'switch organization'); }
    setSwitching(false);
  };

  const createOrg = async () => {
    const name = window.prompt('Name for the new organization');
    if (!name || !name.trim()) return;
    try {
      const created = await api.post('/orgs', { name: name.trim() });
      await switchTo(created.id);
    } catch (e) { fail(e, 'create the organization'); }
  };

  const afterDelete = async () => {
    const other = session.orgs.find((o) => o.id !== session.orgId && o.status === 'active');
    if (other) await switchTo(other.id);
    else onSignOut();
  };

  const Current = cards.find((c) => c.key === active)?.View;

  return (
    <div className="shell" data-testid="app-shell" data-org-id={session.orgId} data-org-theme={org?.theme ?? 'slate'}>
      <aside className="rail">
        <div className="org-now">
          <span className="org-label">Organization</span>
          <strong className="org-name">{org?.name}</strong>
          <span className="role">Your role: <b data-testid="active-role">{session.role}</b></span>
        </div>

        <nav className="orgs" aria-label="Your organizations">
          {session.orgs.map((o) => (
            <button key={o.id} type="button" data-testid="org-option" data-org-id={o.id} data-theme={o.theme}
              className={o.id === session.orgId ? 'org-option current' : 'org-option'}
              aria-current={o.id === session.orgId ? 'true' : undefined}
              disabled={switching} onClick={() => switchTo(o.id)}>
              <span className="swatch" aria-hidden="true" />
              <span>{o.name}</span>
              {o.status === 'suspended' && <span className="tag">suspended</span>}
            </button>
          ))}
          <button type="button" data-testid="create-org" className="org-create" onClick={createOrg}>New organization</button>
        </nav>

        <div className="me">
          <span>{session.user.name}</span>
          <span className="muted">{session.user.email}</span>
          <button type="button" className="link" data-testid="sign-out" onClick={onSignOut}>Sign out</button>
        </div>
      </aside>

      <div className="stage">
        <nav className="cards" aria-label="Sections">
          {cards.map((c) => (
            <button key={c.key} type="button" data-testid={`nav-${c.key}`} className={c.key === active ? 'card-tab current' : 'card-tab'}
              aria-current={c.key === active ? 'page' : undefined} onClick={() => setActive(c.key)}>
              {c.label}
            </button>
          ))}
        </nav>

        <Notice notice={notice} onDismiss={clear} />

        <main ref={mainRef} className="content">
          {Current ? (
            // Keyed by org and card: switching remounts and refetches, so nothing from
            // the previous org can linger on screen.
            <Current key={`${session.orgId}:${active}`} api={api} session={session}
              onRenamed={() => api.switchOrg(session.orgId)} onDeleted={afterDelete} />
          ) : (
            <div className="empty">
              <p>{session.permissions['device:list']?.reason === 'suspended'
                ? 'Your membership in this organization is suspended, so there is nothing you can open here.'
                : 'You have no access to any section of this organization.'}</p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

// --- invite redemption ----------------------------------------------------------

function InvitePage({ api, token }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [accepted, setAccepted] = useState(false);
  const [submitError, setSubmitError] = useState(null);

  useEffect(() => {
    api.peekInvite(token).then(setInvite).catch((e) => setError(
      e.code === 'GONE' ? 'This invite has expired or was cancelled. Ask for a new one.'
        : e.code === 'CONFLICT' ? 'This invite has already been used. Sign in instead.'
          : 'This invite link is not valid. Check that you copied the whole link.'
    ));
  }, [token]);

  const accept = async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setSubmitError(null);
    try {
      await api.acceptInvite(token, { name: form.get('name'), password: form.get('password') });
      window.history.replaceState(null, '', '/');
      setAccepted(true);
    } catch (e) { setSubmitError(e.message); }
  };

  if (accepted) return <Login api={api} banner="You've joined. Sign in with your email and new password." />;

  return (
    <main className="login">
      <h1>RemoteOps</h1>
      {error && <p className="notice notice-error" data-testid="invite-error" role="alert">{error}</p>}
      {!error && !invite && <p className="muted">Checking your invite…</p>}
      {invite && (
        <form onSubmit={accept}>
          <p>You've been invited to <strong>{invite.orgName}</strong> as <strong data-testid="invite-role">{invite.role}</strong>.</p>
          <label>Email <input data-testid="invite-email" value={invite.email} readOnly /></label>
          <label>Your name <input data-testid="invite-name" name="name" required maxLength={100} /></label>
          <label>Password <input data-testid="invite-password" name="password" type="password" minLength={8} required autoComplete="new-password" />
            <span className="hint">At least 8 characters. If you already have an account, use its password.</span>
          </label>
          {submitError && <p className="notice notice-error" role="alert">{submitError}</p>}
          <button type="submit" className="primary" data-testid="invite-submit">Join organization</button>
        </form>
      )}
    </main>
  );
}
