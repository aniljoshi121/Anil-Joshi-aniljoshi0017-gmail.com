import React, { useEffect, useState } from 'react';
import { Notice, useNotice, when } from '../ui.jsx';

const PAGE = 50;

export default function Audit({ api, session }) {
  const [events, setEvents] = useState(null);
  const [more, setMore] = useState(false);
  const { notice, fail, clear } = useNotice();
  const org = session.orgId;

  const load = async (offset = 0) => {
    try {
      const r = await api.get(`/orgs/${org}/audit?limit=${PAGE}&offset=${offset}`);
      setEvents((prev) => (offset === 0 ? r.events : [...prev, ...r.events]));
      setMore(r.events.length === PAGE);
    } catch (e) { fail(e, 'load the audit log'); }
  };
  useEffect(() => { load(0); }, [org]);

  return (
    <section className="view">
      <header className="view-head"><h2>Audit log</h2></header>
      <p className="lede">Every change and every refused attempt, newest first. Entries can't be edited or deleted.</p>
      <Notice notice={notice} onDismiss={clear} />

      {events === null ? <p className="muted">Loading audit log…</p> : events.length === 0 ? (
        <div className="empty"><p>Nothing has happened here yet.</p></div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Result</th><th>Reason</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id} data-testid="audit-row" data-result={e.result}>
                  <td>{when(e.at)}</td>
                  <td>{e.actor_email ?? 'system'}</td>
                  <td className="strong">{e.action}</td>
                  <td className="muted">{e.target_type ? `${e.target_type} ${e.target_id ?? ''}` : ''}</td>
                  <td><span className={`effect effect-${e.result}`}>{e.result === 'allow' ? 'done' : 'refused'}</span></td>
                  <td className="muted">{e.reason_code}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {more && <button type="button" onClick={() => load(events.length)}>Load older entries</button>}
    </section>
  );
}
