import React from 'react';
import { PermButton, Notice, useNotice } from '../ui.jsx';

export default function Admin({ api, session, onRenamed, onDeleted }) {
  const { notice, ok, fail, clear } = useNotice();
  const org = session.orgs.find((o) => o.id === session.orgId);

  const rename = async () => {
    const name = window.prompt('New organization name', org?.name ?? '');
    if (!name || name === org?.name) return;
    try {
      await api.patch(`/orgs/${session.orgId}`, { name });
      ok(`Renamed to ${name}.`);
      onRenamed();
    } catch (e) { fail(e, 'rename the organization'); }
  };

  const remove = async () => {
    const typed = window.prompt(`This deletes ${org?.name} for everyone and ends all its sessions. Type the organization name to confirm.`);
    if (typed !== org?.name) return;
    try {
      await api.del(`/orgs/${session.orgId}`);
      onDeleted();
    } catch (e) { fail(e, 'delete the organization'); }
  };

  return (
    <section className="view">
      <header className="view-head"><h2>Organization settings</h2></header>
      <Notice notice={notice} onDismiss={clear} />
      <dl className="facts">
        <dt>Name</dt><dd>{org?.name}</dd>
        <dt>Theme</dt><dd>{org?.theme}</dd>
      </dl>
      <div className="actions">
        <PermButton permissions={session.permissions} permission="org:update" testId="rename-org" onClick={rename}>Rename organization</PermButton>
        <PermButton permissions={session.permissions} permission="org:delete" testId="delete-org" className="danger" onClick={remove}>Delete organization</PermButton>
      </div>
    </section>
  );
}
