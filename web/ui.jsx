// Small shared pieces: the permission-gated element, the notice line, formatting.

import React from 'react';

export const allowed = (permissions, key) => permissions?.[key]?.effect === 'allow';

// Present or absent, never disabled. If the server did not resolve `permission` to
// allow, nothing is rendered at all.
export function Gate({ permissions, permission, children }) {
  return allowed(permissions, permission) ? children : null;
}

// A button that exists only when the permission is held, carrying the attributes the
// console contract reads.
export function PermButton({ permissions, permission, testId, children, ...rest }) {
  if (!allowed(permissions, permission)) return null;
  return (
    <button type="button" data-testid={testId} data-permission={permission} data-state="unlocked" {...rest}>
      {children}
    </button>
  );
}

// Result of the last action. Errors are announced (role=alert) and say what happened.
export function Notice({ notice, onDismiss }) {
  if (!notice) return null;
  const isError = notice.kind === 'error';
  return (
    <div className={`notice ${isError ? 'notice-error' : 'notice-ok'}`} role={isError ? 'alert' : 'status'} data-error-code={notice.code ?? undefined}>
      <span>{notice.text}</span>
      <button type="button" className="link" onClick={onDismiss}>Dismiss</button>
    </div>
  );
}

// Turn an API error into a sentence a person can act on.
export function describeError(err, doing) {
  const base = err?.message || 'The request failed.';
  switch (err?.code) {
    case 'FORBIDDEN': return `You can't ${doing}: ${base}.`;
    case 'NOT_FOUND': return `Couldn't ${doing}: it no longer exists or isn't in this organization.`;
    case 'NETWORK': return base;
    default: return `Couldn't ${doing}: ${base}.`;
  }
}

export function useNotice() {
  const [notice, setNotice] = React.useState(null);
  return {
    notice,
    clear: () => setNotice(null),
    ok: (text) => setNotice({ kind: 'ok', text }),
    fail: (err, doing) => setNotice({ kind: 'error', text: describeError(err, doing), code: err?.code }),
  };
}

const timeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
export const when = (iso) => (iso ? timeFmt.format(new Date(iso)) : '');

// Why a device permission is missing, when someone explicitly took it away. Implicit
// absences stay silent: nobody granted them, so there is nothing to explain.
export function explicitDenials(permissions, keys) {
  return keys.filter((k) => permissions?.[k]?.reason === 'explicit_deny');
}

export const PERMISSION_LABELS = {
  'device:view': 'View',
  'device:control': 'Control',
  'device:terminal': 'Terminal',
  'device:file_transfer': 'File transfer',
  'device:update': 'Rename',
  'device:provision': 'Decommission',
};
