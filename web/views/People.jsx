import React, { useEffect, useState } from 'react';
import { PermButton, Gate, Notice, useNotice, allowed, when } from '../ui.jsx';

export default function People({ api, session }) {
  const [members, setMembers] = useState(null);
  const [inviting, setInviting] = useState(false);
  const [lastInvite, setLastInvite] = useState(null);
  const { notice, ok, fail, clear } = useNotice();
  const org = session.orgId;
  const perms = session.permissions;

  const load = () => api.get(`/orgs/${org}/members`).then((r) => setMembers(r.members)).catch((e) => fail(e, 'load people'));
  useEffect(() => { load(); }, [org]);

  const changeRole = async (member, role) => {
    try {
      await api.patch(`/orgs/${org}/members/${member.id}`, { role });
      ok(`${member.name} is now ${role}.`);
    } catch (e) { fail(e, `change ${member.name}'s role`); }
    load();
  };

  const toggleSuspend = async (member) => {
    const suspending = member.status === 'active';
    try {
      if (suspending) await api.post(`/orgs/${org}/members/${member.id}/suspend`);
      else await api.del(`/orgs/${org}/members/${member.id}/suspend`);
      ok(suspending ? `${member.name} is suspended and their sessions have ended.` : `${member.name} is reinstated.`);
      load();
    } catch (e) { fail(e, suspending ? `suspend ${member.name}` : `reinstate ${member.name}`); }
  };

  const remove = async (member) => {
    if (!window.confirm(`Remove ${member.name} from this organization? Their sessions end and their grants here are revoked.`)) return;
    try {
      await api.del(`/orgs/${org}/members/${member.id}`);
      ok(`${member.name} was removed.`);
      load();
    } catch (e) { fail(e, `remove ${member.name}`); }
  };

  const invite = async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const inv = await api.post(`/orgs/${org}/invites`, { email: form.get('email'), role: form.get('role') });
      setLastInvite({ email: inv.email, link: `${window.location.origin}/invite/${inv.inviteToken}` });
      setInviting(false);
      clear();
    } catch (e) { fail(e, 'send the invite'); }
  };

  return (
    <section className="view">
      <header className="view-head">
        <h2>People</h2>
        <PermButton permissions={perms} permission="user:invite" testId="invite-user" className="primary" onClick={() => setInviting((v) => !v)}>
          Invite someone
        </PermButton>
      </header>

      <Notice notice={notice} onDismiss={clear} />

      {inviting && (
        <Gate permissions={perms} permission="user:invite">
          <form className="inline-form" onSubmit={invite}>
            <label>Email <input name="email" type="email" required autoFocus /></label>
            <label>Role
              <select name="role" defaultValue="viewer">{session.roles.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}</select>
            </label>
            <button type="submit" className="primary">Create invite</button>
            <button type="button" className="link" onClick={() => setInviting(false)}>Cancel</button>
          </form>
        </Gate>
      )}

      {lastInvite && (
        <div className="notice notice-ok" role="status">
          <span>Invite link for {lastInvite.email}. It is shown once and works once, so send it now:</span>
          <input className="copy" readOnly value={lastInvite.link} onFocus={(e) => e.target.select()} />
          <button type="button" className="link" onClick={() => setLastInvite(null)}>Done</button>
        </div>
      )}

      {members === null ? <p className="muted">Loading people…</p> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Joined</th><th>Actions</th></tr></thead>
            <tbody>
              {members.map((m) => {
                const self = m.id === session.user.id;
                return (
                  <tr key={m.id} data-testid="user-row" data-user-id={m.id}>
                    <td className="strong">{m.name}{self && <span className="tag">you</span>}</td>
                    <td>{m.email}</td>
                    <td>
                      {!self && allowed(perms, 'user:role:update') ? (
                        <select data-testid="role-select" data-permission="user:role:update" data-state="unlocked" aria-label={`Role for ${m.name}`}
                          value={m.role} onChange={(e) => changeRole(m, e.target.value)}>
                          {session.roles.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
                        </select>
                      ) : m.role}
                    </td>
                    <td><span className={`status status-${m.status}`}>{m.status}</span></td>
                    <td>{when(m.joined_at)}</td>
                    <td>
                      {!self && (
                        <div className="actions">
                          <PermButton permissions={perms} permission="user:remove" testId="suspend-user" onClick={() => toggleSuspend(m)}>
                            {m.status === 'active' ? 'Suspend' : 'Reinstate'}
                          </PermButton>
                          <PermButton permissions={perms} permission="user:remove" testId="remove-user" className="danger" onClick={() => remove(m)}>Remove</PermButton>
                        </div>
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
