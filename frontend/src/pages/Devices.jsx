import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import DeviceFormModal from '../components/DeviceFormModal'
import DeviceTimezoneModal from '../components/DeviceTimezoneModal'
import DeviceProtocolModal from '../components/DeviceProtocolModal'
import DeviceSecurityDrawer from '../components/DeviceSecurityDrawer'
import KebabMenu from '../components/KebabMenu'
import DeviceInfoDrawer from '../components/DeviceInfoDrawer'
import SetClockDrawer from '../components/SetClockDrawer'
import WriteLcdDrawer from '../components/WriteLcdDrawer'
import CommandsDrawer from '../components/CommandsDrawer'
import DeviceUsersDrawer from '../components/DeviceUsersDrawer'
import PasswordConfirmModal from '../components/PasswordConfirmModal'

function StatusBadge({ isOnline }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium ${
        isOnline ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
      }`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${isOnline ? 'bg-green-500' : 'bg-gray-400'}`} />
      {isOnline ? 'Online' : 'Offline'}
    </span>
  )
}

const TRUST_STYLES = {
  approved: 'bg-blue-50 text-blue-700',
  pending: 'bg-amber-100 text-amber-800',
  rejected: 'bg-red-100 text-red-700',
}

function TrustBadge({ status, ipLocked }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
          TRUST_STYLES[status] || 'bg-gray-100 text-gray-500'
        }`}
      >
        {status ? status[0].toUpperCase() + status.slice(1) : 'Unknown'}
      </span>
      {ipLocked && (
        <span
          title="Only pushes from the allowed CIDRs are accepted"
          className="inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-100 text-gray-600"
        >
          IP
        </span>
      )}
    </span>
  )
}

function Toast({ message, type, onDismiss }) {
  useEffect(() => {
    // An error is something to read, not glimpse — "timed out" at 3.5s reads
    // as a flicker. It also stays until dismissed by the next toast.
    const t = setTimeout(onDismiss, type === 'error' ? 10_000 : 3500)
    return () => clearTimeout(t)
  }, [onDismiss, type])

  return (
    <div
      className={`fixed bottom-6 right-6 px-4 py-3 rounded-lg shadow-lg text-sm font-medium text-white z-50 ${
        type === 'error' ? 'bg-red-600' : 'bg-gray-900'
      }`}
    >
      {message}
    </div>
  )
}

const PULL_KINDS = { employees: 'Employees', attendance: 'Attendance', templates: 'Templates' }

function formatRelative(iso) {
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)} h ago`
  return new Date(iso).toLocaleDateString()
}

// What the last SDK pull of each kind did (DeviceOut.pull_outcomes). The pull
// runs in the background after the server has already said "started", so
// this column is the ONLY place a failure — a timed-out connect, a refused
// comm key — is visible without reading the server log. Shown per kind and
// never collapsed to the latest one: Sync All runs three pulls, and a
// successful template read must not hide the attendance read that failed.
function LastSyncCell({ outcomes }) {
  const kinds = Object.keys(PULL_KINDS).filter((k) => outcomes?.[k])
  if (kinds.length === 0) return <span className="text-gray-400">—</span>
  return (
    <ul className="space-y-0.5">
      {kinds.map((kind) => {
        const o = outcomes[kind]
        return (
          <li
            key={kind}
            title={`${PULL_KINDS[kind]} · ${new Date(o.at).toLocaleString()}${o.seconds != null ? ` · took ${o.seconds}s` : ''}\n${o.detail}`}
            className={`text-xs ${o.ok ? 'text-gray-600' : 'text-red-700 font-medium'}`}
          >
            <span className={o.ok ? 'text-green-600' : 'text-red-600'}>{o.ok ? '✓' : '✗'}</span>{' '}
            {PULL_KINDS[kind]} · {formatRelative(o.at)}
            {o.seconds != null && <span className="text-gray-400"> · {Math.round(o.seconds)}s</span>}
            {!o.ok && <span className="block font-normal text-red-600 truncate max-w-[16rem]">{o.detail}</span>}
          </li>
        )
      })}
    </ul>
  )
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// Wait for the background pull(s) started by a Sync click to finish, by
// watching the device row for a NEWER outcome of each kind than the one it
// had before the click. Resolves to the fresh outcomes, or null when nothing
// arrived within the budget (an SDK connect times out after 30s; Sync All is
// three of those in a row, and a device with a year of backlog reads slowly).
async function waitForPullOutcomes(sn, kinds, before, budgetMs = 180_000) {
  const started = Date.now()
  while (Date.now() - started < budgetMs) {
    await sleep(2000)
    let device
    try {
      device = await api.devices.get(sn)
    } catch {
      continue
    }
    const outcomes = device.pull_outcomes || {}
    if (kinds.every((k) => outcomes[k] && outcomes[k].at !== before?.[k]?.at)) {
      return outcomes
    }
  }
  return null
}

export default function Devices() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [devices, setDevices] = useState([])
  const [pairing, setPairing] = useState(null)
  const [loading, setLoading] = useState(true)
  const [modal, setModal] = useState(null)
  const [tzModal, setTzModal] = useState(null)   // device whose timezone is being changed
  const [protoModal, setProtoModal] = useState(null)   // device whose protocol is being changed
  const [drawer, setDrawer] = useState(null) // { type, device }
  const [pwConfirm, setPwConfirm] = useState(null) // { title, description, onConfirm }
  const [toast, setToast] = useState(null)

  const showToast = useCallback((message, type = 'success') => setToast({ message, type }), [])
  const dismissToast = useCallback(() => setToast(null), [])

  const loadDevices = useCallback(async () => {
    try {
      const [list, window] = await Promise.all([api.devices.list(), api.devices.getPairing()])
      setDevices(list)
      setPairing(window)
    } catch {
      showToast('Failed to load devices', 'error')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => {
    loadDevices()
    const interval = setInterval(loadDevices, 10_000)
    return () => clearInterval(interval)
  }, [loadDevices])

  async function handleApprove(device) {
    try {
      await api.devices.approve(device.serial_number)
      showToast(`${device.name || device.serial_number} approved`)
      loadDevices()
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handleReject(device) {
    try {
      await api.devices.reject(device.serial_number)
      showToast(`${device.name || device.serial_number} rejected`)
      loadDevices()
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handlePairing(open) {
    try {
      const window = open ? await api.devices.openPairing() : await api.devices.closePairing()
      setPairing(window)
      showToast(open ? 'Pairing window open' : 'Pairing window closed')
      loadDevices()
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handleSave(formData) {
    if (modal.mode === 'create') {
      await api.devices.create(formData)
      showToast('Device added')
    } else {
      await api.devices.update(modal.device.serial_number, formData)
      showToast('Device updated')
    }
    setModal(null)
    loadDevices()
  }

  async function handleSaveTimezone(timezone) {
    const updated = await api.devices.setTimezone(tzModal.serial_number, timezone)
    showToast(`Timezone set to ${updated.timezone}`)
    setTzModal(null)
    loadDevices()
  }

  async function handleSaveProtocol(protocol) {
    const updated = await api.devices.setProtocol(protoModal.serial_number, protocol)
    showToast(`Protocol set to ${updated.protocol}`)
    setProtoModal(null)
    loadDevices()
  }

  async function handleDelete(device) {
    if (!confirm(`Remove "${device.name || device.serial_number}"?`)) return
    try {
      await api.devices.delete(device.serial_number)
      showToast('Device removed')
      loadDevices()
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handleSync(device, type) {
    const labels = {
      all: 'Sync All',
      employees: 'Sync Employees',
      attendance: 'Sync Attendance',
      templates: 'Sync Templates',
    }
    const calls = {
      all: () => api.devices.pull(device.serial_number),
      employees: () => api.devices.pullEmployees(device.serial_number),
      attendance: () => api.devices.pullAttendance(device.serial_number),
      templates: () => api.devices.pullTemplates(device.serial_number),
    }
    // Which background pulls this click starts on an `att` device. The
    // manual template pull is synchronous and reports in its own response.
    const pullKinds = {
      all: ['employees', 'attendance', 'templates'],
      employees: ['employees'],
      attendance: ['attendance'],
      templates: [],
    }[type]
    const name = device.name || device.serial_number
    let result
    try {
      result = await calls[type]()
    } catch (err) {
      showToast(err.message, 'error')
      return
    }
    // An `acc` terminal is never dialled: the server queues a DATA QUERY and
    // the device answers on its next poll, so the response says what really
    // happened and that is what gets shown. Reporting "started" for work
    // that has only been enqueued is the thing this avoids.
    if (result?.status === 'queued' || pullKinds.length === 0) {
      showToast(result?.message || `${labels[type]} done for ${name}`)
      return
    }
    // "started" is all the server can honestly say at this point — the pull
    // is a background task. So say it, then watch the device row for what
    // the pull actually did and report THAT, in red if it failed. Before
    // this, a timed-out connect was visible only in the server log.
    showToast(`${labels[type]} started for ${name}…`)
    const outcomes = await waitForPullOutcomes(device.serial_number, pullKinds, device.pull_outcomes)
    loadDevices()
    if (!outcomes) {
      showToast(`${labels[type]} on ${name}: no result after 3 minutes — check the server log`, 'error')
      return
    }
    const failed = pullKinds.filter((k) => !outcomes[k].ok)
    if (failed.length > 0) {
      showToast(
        `${labels[type]} failed on ${name} — ` +
          failed.map((k) => `${PULL_KINDS[k]}: ${outcomes[k].detail}`).join('; '),
        'error'
      )
    } else {
      showToast(
        `${labels[type]} done on ${name} — ` +
          pullKinds.map((k) => outcomes[k].detail).join('; ')
      )
    }
  }

  function confirmAction(title, description, action) {
    setPwConfirm({ title, description, onConfirm: action })
  }

  // The three device-control actions share one rule, the same one the sync
  // actions follow: on an access-control terminal the server has QUEUED
  // something, not done it, and it says so in `message`. Where a message comes
  // back it is shown verbatim rather than being replaced with a cheerful past
  // tense that would be false.
  async function handleClearAttendance(device) {
    try {
      const result = await api.devices.clearAttendance(device.serial_number)
      showToast(
        result?.message ||
          `Attendance cleared on ${device.name || device.serial_number}`
      )
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handleRestart(device) {
    try {
      const result = await api.devices.restart(device.serial_number)
      showToast(
        result?.message ||
          `${device.name || device.serial_number} is restarting`
      )
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handleUnlock(device) {
    try {
      const result = await api.devices.unlock(device.serial_number)
      // "Door unlocked" is only true on the SDK transport, where the call
      // returned because the door opened. On a queued unlock the honest
      // report is the server's, which says queued and states the delay.
      showToast(
        result?.message ||
          `Door unlocked on ${device.name || device.serial_number}`
      )
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  function menuItems(device) {
    // Which sync actions exist at all depends on the protocol, because the two
    // families are read over different transports. An access-control terminal
    // has no pull for attendance — it pushes punches up by itself — so that
    // item is shown unavailable WITH THE REASON rather than hidden (an
    // operator cannot troubleshoot a menu entry that is not there) and rather
    // than left clickable (it would dial TCP 4370 and time out).
    const isAcc = (device.protocol || 'att') === 'acc'

    return [
      { label: 'Sync All', onClick: () => handleSync(device, 'all') },
      { label: 'Sync Employees', onClick: () => handleSync(device, 'employees') },
      isAcc
        ? {
            label: 'Sync Attendance',
            disabled: true,
            hint: 'Not applicable — this terminal pushes punches up by itself, including anything it buffered while offline.',
          }
        : { label: 'Sync Attendance', onClick: () => handleSync(device, 'attendance') },
      { label: 'Sync Templates', onClick: () => handleSync(device, 'templates') },
      'divider',
      { label: 'Manage Users', onClick: () => setDrawer({ type: 'users', device }) },
      { label: 'Device Info', onClick: () => setDrawer({ type: 'info', device }) },
      { label: 'Set Clock', onClick: () => setDrawer({ type: 'clock', device }) },
      // No command in the access-control protocol addresses the screen, so
      // this is shown unavailable with the reason rather than left clickable
      // (it would open a drawer whose only possible outcome is a 501).
      isAcc
        ? {
            label: 'Write LCD',
            disabled: true,
            hint: 'Not available — the access-control protocol has no command for writing to the screen.',
          }
        : { label: 'Write LCD', onClick: () => setDrawer({ type: 'lcd', device }) },
      // The door DOES work here, but it is not the same action it is on an
      // SDK device and the menu says so before it is clicked. See handleUnlock.
      isAcc
        ? {
            label: 'Unlock Door',
            onClick: () => handleUnlock(device),
            hint: 'Queued — the door opens when the terminal next polls, usually within ~10s, not instantly.',
          }
        : { label: 'Unlock Door', onClick: () => handleUnlock(device) },
      { label: 'Commands', onClick: () => setDrawer({ type: 'commands', device }) },
      'divider',
      {
        label: 'Clear Attendance',
        danger: true,
        onClick: () => confirmAction(
          'Clear Attendance',
          isAcc
            ? `This will permanently wipe the access-control records held on the terminal. Records already synced to the database are kept. The command is queued and runs when the terminal next polls — nothing is deleted at the moment you confirm.`
            : `This will permanently wipe attendance logs from the device memory. Records already synced to the database are kept.`,
          () => { setPwConfirm(null); handleClearAttendance(device) }
        ),
      },
      {
        label: 'Restart Device',
        danger: true,
        onClick: () => confirmAction(
          'Restart Device',
          isAcc
            ? `The terminal will reboot. The command is queued and runs when it next polls, so it will not restart at the moment you confirm. It goes offline briefly and reconnects automatically.`
            : `The device will reboot. It will go offline briefly and reconnect automatically.`,
          () => { setPwConfirm(null); handleRestart(device) }
        ),
      },
      'divider',
      { label: 'Device Security', onClick: () => setDrawer({ type: 'security', device }) },
      { label: 'Edit', onClick: () => setModal({ mode: 'edit', device }) },
      { label: 'Delete', danger: true, onClick: () => handleDelete(device) },
    ]
  }

  function formatDate(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleString()
  }

  function formatTime(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleTimeString()
  }

  const pendingDevices = devices.filter((d) => d.status === 'pending')

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-gray-900">Devices</h1>
        <div className="flex items-center gap-3">
          {isAdmin && (
            pairing?.is_open ? (
              <div className="flex items-center gap-2 text-sm">
                <span className="text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-1.5">
                  Pairing open until {formatTime(pairing.open_until)}
                </span>
                <button
                  onClick={() => handlePairing(false)}
                  className="border border-gray-200 hover:bg-gray-50 text-gray-700 text-sm font-medium px-3 py-2 rounded-lg transition-colors"
                >
                  Close Pairing
                </button>
              </div>
            ) : (
              <button
                onClick={() => handlePairing(true)}
                title="Briefly accept serials this server has never seen, so they can be approved"
                className="border border-gray-200 hover:bg-gray-50 text-gray-700 text-sm font-medium px-3 py-2 rounded-lg transition-colors"
              >
                Open Pairing
              </button>
            )
          )}
          <button
            onClick={() => setModal({ mode: 'create' })}
            className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
          >
            + Add Device
          </button>
        </div>
      </div>

      {pendingDevices.length > 0 && (
        <div className="bg-amber-50 border border-amber-200 rounded-xl mb-6">
          <div className="px-4 py-3 border-b border-amber-200">
            <h2 className="text-sm font-semibold text-amber-900">Waiting for approval</h2>
            <p className="text-xs text-amber-700 mt-0.5">
              These serials contacted the server but push nothing until approved.
            </p>
          </div>
          <table className="w-full text-sm">
            <tbody>
              {pendingDevices.map((device) => (
                <tr key={device.serial_number} className="border-b border-amber-100 last:border-0">
                  <td className="px-4 py-3 font-mono text-xs text-gray-700">{device.serial_number}</td>
                  <td className="px-4 py-3 text-gray-500">from {device.last_ip || '—'}</td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{formatDate(device.last_seen || device.created_at)}</td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex gap-2 justify-end">
                      <button
                        onClick={() => handleApprove(device)}
                        disabled={!isAdmin}
                        className="bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition-colors"
                      >
                        Approve
                      </button>
                      <button
                        onClick={() => handleReject(device)}
                        disabled={!isAdmin}
                        className="border border-red-200 text-red-600 hover:bg-red-50 disabled:opacity-40 text-xs font-medium px-3 py-1.5 rounded-lg transition-colors"
                      >
                        Reject
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* A standing banner, not a toast. An access revocation that the door
          has not confirmed does not stop being true because somebody looked
          away, and it is the one queue state in this application where
          waiting is a hazard rather than a feature. */}
      {devices.some((d) => d.pending_revocations > 0) && (
        <div className="mb-4 border-2 border-red-300 bg-red-50 rounded-xl px-4 py-3">
          <p className="text-sm font-semibold text-red-800">
            Access revocations are waiting to reach a door
          </p>
          <p className="text-xs text-red-700 mt-1">
            These people have been removed in the system but the terminal has
            not collected and confirmed it, so they can still get in. A device
            that is offline will not collect anything until it comes back.
          </p>
          <ul className="mt-2 space-y-0.5">
            {devices
              .filter((d) => d.pending_revocations > 0)
              .map((d) => (
                <li key={d.serial_number} className="text-xs text-red-800">
                  <span className="font-medium">{d.name || d.serial_number}</span>
                  {' — '}
                  {d.pending_revocations} outstanding
                  {!d.is_online && ' · device is offline'}
                </li>
              ))}
          </ul>
        </div>
      )}

      <div className="bg-white rounded-xl border border-gray-200">
        {loading ? (
          <div className="p-12 text-center text-sm text-gray-400">Loading…</div>
        ) : devices.length === 0 ? (
          <div className="p-12 text-center text-sm text-gray-400">
            No devices registered yet. Add one to get started.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50 [&>th:first-child]:rounded-tl-xl [&>th:last-child]:rounded-tr-xl">
                <th className="text-left px-4 py-3 font-medium text-gray-500">Name</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Serial</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Address</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Status</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Trust</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Timezone</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Protocol</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Last Seen</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Last Sync</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => (
                <tr
                  key={device.serial_number}
                  className="border-b border-gray-100 last:border-0 hover:bg-gray-50 transition-colors"
                >
                  <td className="px-4 py-3 font-medium text-gray-900">
                    {device.name || <span className="text-gray-400">—</span>}
                    {/* An outstanding revocation is a safety state, not a
                        queue statistic: somebody has been taken off this door
                        in the system and the door has not been told. It is
                        surfaced here as well as on the person's page because
                        an operator scanning this table for "is anything
                        wrong" should not have to open every employee to find
                        it. */}
                    {device.pending_revocations > 0 && (
                      <span className="block mt-1 text-xs font-semibold text-red-700">
                        {device.pending_revocations} revocation
                        {device.pending_revocations > 1 ? 's' : ''} not confirmed
                        at this door
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-500 font-mono text-xs">{device.serial_number}</td>
                  <td className="px-4 py-3 text-gray-500">{device.ip_address}:{device.port}</td>
                  <td className="px-4 py-3"><StatusBadge isOnline={device.is_online} /></td>
                  <td className="px-4 py-3">
                    <TrustBadge status={device.status} ipLocked={device.ip_check_enabled} />
                  </td>
                  <td className="px-4 py-3">
                    {/* Read-only. Changing it relabels every record this device
                        pushed, so it is edited only through its own modal. */}
                    <span className="inline-flex items-center gap-2">
                      <span className="text-gray-600 text-xs">{device.timezone || '—'}</span>
                      {isAdmin && (
                        <button
                          onClick={() => setTzModal(device)}
                          title="Change what this device's punch times mean"
                          aria-label={`Change timezone for ${device.serial_number}`}
                          data-testid={`edit-timezone-${device.serial_number}`}
                          className="text-xs text-blue-500 hover:text-blue-700 underline"
                        >
                          Edit
                        </button>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {/* Read-only. Normally set automatically from what the
                        device announces (D9); an operator corrects it only
                        through its own modal, which pins the value. */}
                    <span className="inline-flex items-center gap-2">
                      <span className="text-gray-600 text-xs">
                        {device.protocol || 'att'}
                        {device.protocol_pinned && (
                          <span
                            title="Manually set — pinned against automatic reclassification until the device sends contradicting evidence"
                            className="ml-1 text-[10px] text-amber-700 bg-amber-50 border border-amber-200 rounded px-1 py-0.5"
                          >
                            pinned
                          </span>
                        )}
                      </span>
                      {isAdmin && (
                        <button
                          onClick={() => setProtoModal(device)}
                          title="Correct which PUSH protocol this device is treated as speaking"
                          aria-label={`Change protocol for ${device.serial_number}`}
                          data-testid={`edit-protocol-${device.serial_number}`}
                          className="text-xs text-blue-500 hover:text-blue-700 underline"
                        >
                          Edit
                        </button>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{formatDate(device.last_seen)}</td>
                  <td className="px-4 py-3"><LastSyncCell outcomes={device.pull_outcomes} /></td>
                  <td className="px-4 py-3 text-right">
                    <KebabMenu items={menuItems(device)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modal && (
        <DeviceFormModal
          mode={modal.mode}
          device={modal.device}
          onSave={handleSave}
          onClose={() => setModal(null)}
        />
      )}

      {tzModal && (
        <DeviceTimezoneModal
          device={tzModal}
          onSave={handleSaveTimezone}
          onClose={() => setTzModal(null)}
        />
      )}

      {protoModal && (
        <DeviceProtocolModal
          device={protoModal}
          onSave={handleSaveProtocol}
          onClose={() => setProtoModal(null)}
        />
      )}

      {drawer?.type === 'users' && (
        <DeviceUsersDrawer
          device={drawer.device}
          onClose={() => setDrawer(null)}
          showToast={showToast}
        />
      )}
      {drawer?.type === 'info' && (
        <DeviceInfoDrawer
          device={drawer.device}
          onClose={() => setDrawer(null)}
          showToast={showToast}
        />
      )}
      {drawer?.type === 'clock' && (
        <SetClockDrawer
          device={drawer.device}
          onClose={() => setDrawer(null)}
          showToast={showToast}
        />
      )}
      {drawer?.type === 'lcd' && (
        <WriteLcdDrawer
          device={drawer.device}
          onClose={() => setDrawer(null)}
          showToast={showToast}
        />
      )}
      {drawer?.type === 'security' && (
        <DeviceSecurityDrawer
          device={drawer.device}
          onClose={() => setDrawer(null)}
          onSaved={loadDevices}
          showToast={showToast}
        />
      )}
      {drawer?.type === 'commands' && (
        <CommandsDrawer
          device={drawer.device}
          onClose={() => setDrawer(null)}
          showToast={showToast}
          onChange={loadDevices}
        />
      )}

      {pwConfirm && (
        <PasswordConfirmModal
          title={pwConfirm.title}
          description={pwConfirm.description}
          onConfirm={pwConfirm.onConfirm}
          onClose={() => setPwConfirm(null)}
        />
      )}

      {toast && <Toast message={toast.message} type={toast.type} onDismiss={dismissToast} />}
    </>
  )
}
