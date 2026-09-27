import React, { useEffect, useState } from 'react';
import { PermButton, Notice, useNotice, allowed, when } from '../ui.jsx';

const END_REASONS = {
  user_stopped: 'stopped by its owner',
  admin_terminated: 'ended by an admin',
  session_expired: 'reached its time limit',
  user_suspended: 'owner was suspended',
  membership_removed: 'owner left the organization',
  device_transferred: 'device was moved or decommissioned',
  superseded: 'replaced by a newer session',
};

export default function Sessions({ api, session }) {
  const [sessions, setSessions] = useState(null);
  const [devices, setDevices] = useState([]);
  const [starting, setStarting] = useState(false);
  const { notice, ok, fail, clear } = useNotice();
  const org = session.orgId;
  const perms = session.permissions;

  const load = () => api.get(`/orgs/${org}/sessions`).then((r) => setSessions(r.sessions)).catch((e) => fail(e, 'load sessions'));
  useEffect(() => { load(); }, [org]);

  const openStart = async () => {
    setStarting((v) => !v);
    try { setDevices((await api.get(`/orgs/${org}/devices`)).devices); } catch { setDevices([]); }
  };

  const start = async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      await api.post(`/orgs/${org}/sessions`, { deviceId: form.get('deviceId'), mode: form.get('mode') });
      ok('Session started.');
      setStarting(false);
      load();
    } catch (e) { fail(e, 'start the session'); }
  };

  const stop = async (s) => {
    try {
      await api.del(`/sessions/${s.id}`);
      ok('Session ended.');
      load();
    } catch (e) { fail(e, 'end the session'); }
  };

  return (
    <section className="view">
      <header className="view-head">
        <h2>Sessions</h2>
        <PermButton permissions={perms} permission="session:start" testId="new-session" className="primary" onClick={openStart}>
          Start a session
        </PermButton>
      </header>
      <p className="lede">Sessions are records of access, not live connections. Changing someone's permissions never cuts off a session already running; it ends at its time limit.</p>

      <Notice notice={notice} onDismiss={clear} />

      {starting && (
        <form className="inline-form" onSubmit={start}>
          <label>Device
            <select name="deviceId" required defaultValue="">
              <option value="" disabled>Choose a device</option>
              {devices.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          </label>
          <label>Mode
            <select name="mode" defaultValue="view">
              <option value="view">View</option>
              <option value="control">Control</option>
              <option value="terminal">Terminal</option>
            </select>
          </label>
          <button type="submit" className="primary">Start</button>
          <button type="button" className="link" onClick={() => setStarting(false)}>Cancel</button>
        </form>
      )}

      {sessions === null ? <p className="muted">Loading sessions…</p> : sessions.length === 0 ? (
        <div className="empty"><p>No sessions in this organization yet.</p></div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Device</th><th>Person</th><th>Mode</th><th>State</th><th>Started</th><th>Ends</th><th></th></tr></thead>
            <tbody>
              {sessions.map((s) => {
                const own = s.user_id === session.user.id;
                const canStop = s.state === 'active' && (own || allowed(perms, 'session:terminate'));
                return (
                  <tr key={s.id} data-testid="session-row" data-session-id={s.id}>
                    <td className="strong">{s.device_name}</td>
                    <td>{s.user_email}{own && <span className="tag">you</span>}</td>
                    <td>{s.mode}</td>
                    <td>
                      <span className={`status status-${s.state}`}>{s.state}</span>
                      {s.end_reason && <span className="muted"> {END_REASONS[s.end_reason] ?? s.end_reason}</span>}
                    </td>
                    <td>{when(s.started_at)}</td>
                    <td>{when(s.ended_at ?? s.expires_at)}</td>
                    <td>
                      {canStop && (
                        <button type="button" data-testid="stop-session" data-permission={own ? undefined : 'session:terminate'} data-state="unlocked" onClick={() => stop(s)}>
                          {own ? 'Stop' : 'End session'}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
