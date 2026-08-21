import { useState } from 'react'
import { api } from '../api'

// One revocation, one card (E13). `group` is a RevocationGroupOut from
// GET /devices/{sn}/revocations: the two `DATA DELETE` commands E8 sends
// already merged server-side, by (device_sn, pin) — not re-derived here, so
// Employees.jsx and CommandsDrawer.jsx cannot drift into grouping two
// commands two different ways, which is how a UI ended up offering a
// "Cancel" per command instead of per revocation in the first place.
//
// `group.split` is the one case tidiness must lose to honesty: the two
// commands genuinely in different states (one acknowledged, one still
// outstanding; one refused, one pending). Averaging that into one status
// line would hide exactly the half-revocation this unit exists to surface.

const ROLE_NAME = { user: 'user record', userauthorize: 'door permission' }

function roleLine(role, entry) {
  const name = ROLE_NAME[role]
  if (!entry) return `${name}: never queued`
  if (entry.outstanding) {
    return entry.state === 'sent'
      ? `${name}: delivered to the device — waiting for it to confirm`
      : `${name}: waiting for the device to poll`
  }
  switch (entry.state) {
    case 'acknowledged':
      return `${name}: confirmed by the device`
    case 'refused':
      return `${name}: refused by the device (Return=${entry.return_code})`
    case 'unconfirmed':
      // E11: a positive code this system cannot read. Not a refusal, not a
      // confirmation — say exactly that, nothing stronger.
      return `${name}: answered with a code this system cannot read ` +
        `(Return=${entry.return_code}) — not a refusal, not a confirmation`
    case 'cancelled':
      return `${name}: cancelled before delivery`
    default:
      return `${name}: never acknowledged — the server gave up on it`
  }
}

// Timestamps come back naive-UTC from the API; anchor them before diffing,
// or a UTC+4 browser reads a fresh command as hours old.
function since(iso) {
  if (!iso) return ''
  const stamp = /(Z|[+-]\d\d:?\d\d)$/.test(iso) ? iso : `${iso}Z`
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(stamp).getTime()) / 1000))
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}

export default function RevocationCard({ group, title, cancelLabel, onCancelled, onError }) {
  const [busy, setBusy] = useState(false)
  const { user, userauthorize, split, still_open } = group

  // Cancelling calls E8's revocation-level DELETE, atomically, for BOTH
  // commands — never a per-command cancel. That is the actual correctness
  // fix here: two "Cancel" buttons on two cards each cancelling only their
  // own command is exactly the half-revocation this unit exists to close.
  async function handleCancel() {
    setBusy(true)
    try {
      const res = await api.devices.cancelRevocation(group.device_sn, group.user_id)
      onCancelled?.(res)
    } catch (err) {
      onError?.(err)
    } finally {
      setBusy(false)
    }
  }

  const outstanding = user?.outstanding ? user : userauthorize?.outstanding ? userauthorize : null

  return (
    <div className="bg-white rounded-lg px-3 py-2.5 text-sm">
      <div className="flex items-center gap-2">
        <p className="text-gray-900 font-semibold flex-1 min-w-0 truncate">{title}</p>
        <span
          className={`text-xs px-1.5 py-0.5 rounded-full font-semibold whitespace-nowrap ${
            still_open ? 'bg-red-600 text-white' : 'bg-amber-100 text-amber-800'
          }`}
        >
          {still_open ? 'Still open' : 'Clearing up'}
        </span>
      </div>

      {split ? (
        <div className={`text-xs mt-1 space-y-0.5 ${still_open ? 'text-red-700' : 'text-amber-800'}`}>
          <p>{roleLine('user', user)}</p>
          <p>{roleLine('userauthorize', userauthorize)}</p>
        </div>
      ) : (
        <p className={`text-xs mt-1 ${still_open ? 'text-red-700' : 'text-amber-800'}`}>
          {user.state === 'sent'
            ? 'Handed to the device — waiting for it to confirm the removal'
            : 'Waiting for the device to poll. Nothing has reached it yet.'}
          {outstanding?.created_at && <> · outstanding {since(outstanding.created_at)}</>}
        </p>
      )}

      {cancelLabel && (
        <button
          onClick={handleCancel}
          disabled={busy}
          className="mt-2 text-xs text-gray-600 hover:text-gray-900 px-2 py-1 rounded hover:bg-gray-100 disabled:opacity-40 transition-colors"
        >
          {busy ? 'Cancelling…' : cancelLabel}
        </button>
      )}
    </div>
  )
}
