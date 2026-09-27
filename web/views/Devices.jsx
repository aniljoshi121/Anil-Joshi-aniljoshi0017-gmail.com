import React, { useEffect, useState } from 'react';
import { PermButton, Gate, Notice, useNotice, explicitDenials, PERMISSION_LABELS } from '../ui.jsx';

const KINDS = ['macos', 'windows', 'linux', 'android', 'ios'];
const ROW_ACTIONS = ['device:view', 'device:control', 'device:terminal', 'device:file_transfer', 'device:update', 'device:provision'];

export default function Devices({ api, session }) {
  const [devices, setDevices] = useState(null);
  const [adding, setAdding] = useState(false);
  const { notice, ok, fail, clear } = useNotice();
  const org = session.orgId;

  const load = () =>
    api.get(`/orgs/${org}/devices`).then((r) => setDevices(r.devices)).catch((e) => fail(e, 'load devices'));

  // Fetch on every mount: the rows and their buttons are whatever the server says now.
  useEffect(() => { load(); }, [org]);

  const startSession = async (device, mode) => {
    try {
      await api.post(`/orgs/${org}/sessions`, { deviceId: device.id, mode });
      ok(`Started a ${mode} session on ${device.name}.`);
    } catch (e) { fail(e, `start a ${mode} session on ${device.name}`); }
  };

  const rename = async (device) => {
    const name = window.prompt(`New name for ${device.name}`, device.name);
    if (!name || name === device.name) return;
    try {
      await api.patch(`/orgs/${org}/devices/${device.id}`, { name });
      ok(`Renamed to ${name}.`);
      load();
    } catch (e) { fail(e, 'rename the device'); }
  };

  const decommission = async (device) => {
    if (!window.confirm(`Decommission ${device.name}? Its live sessions end and grants on it are revoked.`)) return;
    try {
      await api.del(`/orgs/${org}/devices/${device.id}`);
      ok(`${device.name} was decommissioned.`);
      load();
    } catch (e) { fail(e, 'decommission the device'); }
  };

  const add = async (event) => {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    try {
      const d = await api.post(`/orgs/${org}/devices`, { name: form.get('name'), kind: form.get('kind') });
      ok(`Added ${d.name}.`);
      setAdding(false);
      load();
    } catch (e) { fail(e, 'add the device'); }
  };

  return (
    <section className="view">
      <header className="view-head">
        <h2>Devices</h2>
        <PermButton permissions={session.permissions} permission="device:provision" testId="add-device" className="primary" onClick={() => setAdding((v) => !v)}>
          Add device
        </PermButton>
      </header>

      <Notice notice={notice} onDismiss={clear} />

      {adding && (
        <Gate permissions={session.permissions} permission="device:provision">
          <form className="inline-form" onSubmit={add}>
            <label>Name <input name="name" required maxLength={100} autoFocus /></label>
            <label>Kind
              <select name="kind" defaultValue="linux">{KINDS.map((k) => <option key={k}>{k}</option>)}</select>
            </label>
            <button type="submit" className="primary">Save device</button>
            <button type="button" className="link" onClick={() => setAdding(false)}>Cancel</button>
          </form>
        </Gate>
      )}

      {devices === null ? <p className="muted">Loading devices…</p> : devices.length === 0 ? (
        <div className="empty" data-testid="devices-empty">
          <p>No devices you can see in this organization yet.</p>
          {session.permissions['device:provision']?.effect === 'allow' && <p className="muted">Use Add device to enrol the first one.</p>}
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Device</th><th>Kind</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody>
              {devices.map((d) => {
                const p = d.permissions;
                const removed = explicitDenials(p, ROW_ACTIONS);
                return (
                  <tr key={d.id} data-testid="device-row" data-device-id={d.id}>
                    <td className="strong">{d.name}</td>
                    <td>{d.kind}</td>
                    <td><span className={`dot ${d.online ? 'on' : 'off'}`} />{d.online ? 'Online' : 'Offline'}</td>
                    <td>
                      <div className="actions">
                        <PermButton permissions={p} permission="device:view" testId="start-view" onClick={() => startSession(d, 'view')}>View</PermButton>
                        <PermButton permissions={p} permission="device:control" testId="start-control" onClick={() => startSession(d, 'control')}>Control</PermButton>
                        <PermButton permissions={p} permission="device:terminal" testId="start-terminal" onClick={() => startSession(d, 'terminal')}>Terminal</PermButton>
                        <PermButton permissions={p} permission="device:file_transfer" testId="transfer-files" onClick={() => ok('File transfer is recorded as a permission only; this console moves no files.')}>Transfer files</PermButton>
                        <PermButton permissions={p} permission="device:update" testId="rename-device" onClick={() => rename(d)}>Rename</PermButton>
                        <PermButton permissions={p} permission="device:provision" testId="decommission-device" className="danger" onClick={() => decommission(d)}>Decommission</PermButton>
                      </div>
                      {removed.length > 0 && (
                        <p className="why">Removed for you by an explicit deny: {removed.map((k) => PERMISSION_LABELS[k] ?? k).join(', ')}.</p>
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
