import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import DeviceFormModal from '../components/DeviceFormModal'
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
  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [modal, setModal] = useState(null)
  const [drawer, setDrawer] = useState(null) // { type, device }
  const [pwConfirm, setPwConfirm] = useState(null) // { title, description, onConfirm }
  const [toast, setToast] = useState(null)

  const showToast = useCallback((message, type = 'success') => setToast({ message, type }), [])
  const dismissToast = useCallback(() => setToast(null), [])

  const loadDevices = useCallback(async () => {
    try {
      setDevices(await api.devices.list())
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
      { label: 'Edit', onClick: () => setModal({ mode: 'edit', device }) },
      { label: 'Delete', danger: true, onClick: () => handleDelete(device) },
    ]
  }

  function formatDate(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleString()
  }

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-gray-900">Devices</h1>
        <button
          onClick={() => setModal({ mode: 'create' })}
          className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
        >
          + Add Device
        </button>
      </div>

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
