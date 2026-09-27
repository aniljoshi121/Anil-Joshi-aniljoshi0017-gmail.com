import React, { useEffect, useState } from 'react';
import { PermButton, Gate, Notice, useNotice, when } from '../ui.jsx';

export default function Grants({ api, session }) {
  const [grants, setGrants] = useState(null);
  const [creating, setCreating] = useState(false);
  const { notice, ok, fail, clear } = useNotice();
  const org = session.orgId;
  const perms = session.permissions;

  const load = () => api.get(`/orgs/${org}/grants`).then((r) => setGrants(r.grants)).catch((e) => fail(e, 'load grants'));
  useEffect(() => { load(); }, [org]);

  const revoke = async (grant) => {
    if (!window.confirm('Revoke this grant? It stops applying on the next request; sessions already running continue until they end.')) return;
    try {
      await api.del(`/orgs/${org}/grants/${grant.id}`);
      ok('Grant revoked.');
      load();
    } catch (e) { fail(e, 'revoke the grant'); }
  };

  return (
    <section className="view">
      <header className="view-head">
        <h2>Grants</h2>
        <PermButton permissions={perms} permission="grant:create" testId="new-grant" className="primary" onClick={() => setCreating((v) => !v)}>
          New grant
        </PermButton>
      </header>
      <p className="lede">A grant adds to or takes away from someone's role, on one device or across the organization. A deny always wins.</p>

      <Notice notice={notice} onDismiss={clear} />

      {creating && (
        <Gate permissions={perms} permission="grant:create">
          <GrantForm api={api} session={session}
            onDone={() => { setCreating(false); ok('Grant created.'); load(); }}
            onError={(e) => fail(e, 'create the grant')}
            onCancel={() => setCreating(false)} />
        </Gate>
      )}

      {grants === null ? <p className="muted">Loading grants…</p> : grants.length === 0 ? (
        <div className="empty"><p>No grants yet. Everyone has exactly their role's permissions.</p></div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Person</th><th>Effect</th><th>Permissions</th><th>Where</th><th>Window</th><th></th></tr></thead>
            <tbody>
              {grants.map((g) => (
                <tr key={g.id} data-testid="grant-row" data-grant-id={g.id} data-effect={g.effect}>
                  <td className="strong">{g.user_email}</td>
                  <td><span className={`effect effect-${g.effect}`}>{g.effect}</span></td>
                  <td className="perm-list">{g.permissions.join(', ')}</td>
                  <td>{g.device_name ?? 'Whole organization'}</td>
                  <td className="muted">
                    {g.starts_at ? `from ${when(g.starts_at)} ` : ''}{g.expires_at ? `until ${when(g.expires_at)}` : (g.starts_at ? '' : 'no end')}
                    {!g.active && ' (not active now)'}
                  </td>
                  <td>
                    <PermButton permissions={perms} permission="grant:revoke" testId="revoke-grant" className="danger" onClick={() => revoke(g)}>Revoke</PermButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function GrantForm({ api, session, onDone, onError, onCancel }) {
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const org = session.orgId;
  // The permission catalogue comes from the server's resolved set, so a permission that
  // exists only in this database still appears here.
  const catalogue = Object.keys(session.permissions).sort();

  useEffect(() => {
    api.get(`/orgs/${org}/members`).then((r) => setMembers(r.members.filter((m) => m.id !== session.user.id && m.status === 'active'))).catch(onError);
    api.get(`/orgs/${org}/devices`).then((r) => setDevices(r.devices)).catch(() => setDevices([]));
  }, [org]);

  const submit = async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const expires = form.get('expiresAt');
    try {
      await api.post(`/orgs/${org}/grants`, {
        userId: form.get('userId'),
        deviceId: form.get('deviceId') || null,
        effect: form.get('effect'),
        permissions: form.getAll('permissions'),
        ...(expires ? { expiresAt: new Date(expires).toISOString() } : {}),
      });
      onDone();
    } catch (e) { onError(e); }
  };

  return (
    <form className="grant-form" onSubmit={submit}>
      <div className="row">
        <label>Person
          <select name="userId" data-testid="grant-user" required defaultValue="">
            <option value="" disabled>Choose someone</option>
            {members.map((m) => <option key={m.id} value={m.id}>{m.name} ({m.role})</option>)}
          </select>
        </label>
        <label>Where
          <select name="deviceId" data-testid="grant-device" defaultValue="">
            <option value="">Whole organization</option>
            {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </label>
        <label>Effect
          <select name="effect" data-testid="grant-effect" defaultValue="allow">
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
        </label>
        <label>Expires (optional)
          <input type="datetime-local" name="expiresAt" data-testid="grant-expires" />
        </label>
      </div>
      <fieldset>
        <legend>Permissions</legend>
        <div className="checks">
          {catalogue.map((key) => (
            <label key={key} className="check">
              <input type="checkbox" name="permissions" value={key} data-permission-key={key} /> {key}
            </label>
          ))}
        </div>
      </fieldset>
      <div className="row">
        <button type="submit" className="primary" data-testid="grant-submit">Create grant</button>
        <button type="button" className="link" onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}
