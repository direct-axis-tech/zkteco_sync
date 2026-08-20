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
    const t = setTimeout(onDismiss, 3500)
    return () => clearTimeout(t)
  }, [onDismiss])

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
    try {
      await calls[type]()
      showToast(`${labels[type]} started for ${device.name || device.serial_number}`)
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  function confirmAction(title, description, action) {
    setPwConfirm({ title, description, onConfirm: action })
  }

  async function handleClearAttendance(device) {
    try {
      await api.devices.clearAttendance(device.serial_number)
      showToast(`Attendance cleared on ${device.name || device.serial_number}`)
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handleRestart(device) {
    try {
      await api.devices.restart(device.serial_number)
      showToast(`${device.name || device.serial_number} is restarting`)
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handleUnlock(device) {
    try {
      await api.devices.unlock(device.serial_number)
      showToast(`Door unlocked on ${device.name || device.serial_number}`)
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  function menuItems(device) {
    return [
      { label: 'Sync All', onClick: () => handleSync(device, 'all') },
      { label: 'Sync Employees', onClick: () => handleSync(device, 'employees') },
      { label: 'Sync Attendance', onClick: () => handleSync(device, 'attendance') },
      { label: 'Sync Templates', onClick: () => handleSync(device, 'templates') },
      'divider',
      { label: 'Manage Users', onClick: () => setDrawer({ type: 'users', device }) },
      { label: 'Device Info', onClick: () => setDrawer({ type: 'info', device }) },
      { label: 'Set Clock', onClick: () => setDrawer({ type: 'clock', device }) },
      { label: 'Write LCD', onClick: () => setDrawer({ type: 'lcd', device }) },
      { label: 'Unlock Door', onClick: () => handleUnlock(device) },
      { label: 'Queue Command', onClick: () => setDrawer({ type: 'commands', device }) },
      'divider',
      {
        label: 'Clear Attendance',
        danger: true,
        onClick: () => confirmAction(
          'Clear Attendance',
          `This will permanently wipe attendance logs from the device memory. Records already synced to the database are kept.`,
          () => { setPwConfirm(null); handleClearAttendance(device) }
        ),
      },
      {
        label: 'Restart Device',
        danger: true,
        onClick: () => confirmAction(
          'Restart Device',
          `The device will reboot. It will go offline briefly and reconnect automatically.`,
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
        <DeviceInfoDrawer device={drawer.device} onClose={() => setDrawer(null)} />
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
