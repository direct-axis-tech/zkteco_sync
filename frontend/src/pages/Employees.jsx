import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'

const PRIVILEGE_LABELS = { 0: 'User', 2: 'Enroller', 14: 'Admin' }

const FINGER_NAMES = [
  'Left Little', 'Left Ring', 'Left Middle', 'Left Index', 'Left Thumb',
  'Right Thumb', 'Right Index', 'Right Middle', 'Right Ring', 'Right Little',
]

function PrivilegeBadge({ privilege }) {
  const label = PRIVILEGE_LABELS[privilege] || `Level ${privilege}`
  const style =
    privilege === 14
      ? 'bg-purple-100 text-purple-700'
      : privilege === 2
      ? 'bg-blue-100 text-blue-700'
      : 'bg-gray-100 text-gray-500'
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium ${style}`}>
      {label}
    </span>
  )
}

function Section({ title, action, children }) {
  return (
    <div className="mb-6">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">{title}</p>
        {action}
      </div>
      {children}
    </div>
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

function DetailPanel({ employee, allDevices }) {
  const [enrolledDevices, setEnrolledDevices] = useState(null)
  const [templates, setTemplates] = useState(null)
  const [toast, setToast] = useState(null)

  // Push to device
  const [pushDeviceSn, setPushDeviceSn] = useState('')
  const [pushing, setPushing] = useState(false)

  // Enroll
  const [enrollDeviceSn, setEnrollDeviceSn] = useState('')
  const [enrollFingerId, setEnrollFingerId] = useState(0)
  const [enrolling, setEnrolling] = useState(false)

  // Per-row busy states
  const [busyDevice, setBusyDevice] = useState({})
  const [busyTemplate, setBusyTemplate] = useState({})

  const showToast = (msg, type = 'success') => setToast({ message: msg, type })

  const reload = useCallback(() => {
    if (!employee) return
    setEnrolledDevices(null)
    setTemplates(null)
    api.employees.getDevices(employee.user_id).then(setEnrolledDevices).catch(() => setEnrolledDevices([]))
    api.employees.getTemplates(employee.user_id).then(setTemplates).catch(() => setTemplates([]))
  }, [employee?.user_id])

  useEffect(() => {
    reload()
  }, [reload])

  if (!employee) {
    return (
      <div className="flex-1 flex items-center justify-center text-sm text-gray-400">
        Select an employee to view details
      </div>
    )
  }

  const enrolledSns = new Set((enrolledDevices || []).map((d) => d.device_sn))
  const unenrolledDevices = allDevices.filter((d) => !enrolledSns.has(d.serial_number))

  async function handlePushToDevice(e) {
    e.preventDefault()
    if (!pushDeviceSn) return
    setPushing(true)
    try {
      await api.devices.pushUser(pushDeviceSn, employee.user_id)
      showToast(`Pushed to ${pushDeviceSn}`)
      setPushDeviceSn('')
      reload()
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setPushing(false)
    }
  }

  async function handleRemoveFromDevice(sn) {
    setBusyDevice((b) => ({ ...b, [sn]: 'removing' }))
    try {
      await api.devices.removeUser(sn, employee.user_id)
      showToast(`Removed from ${sn}`)
      reload()
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setBusyDevice((b) => ({ ...b, [sn]: null }))
    }
  }

  async function handlePushTemplates(sn) {
    setBusyDevice((b) => ({ ...b, [sn]: 'templates' }))
    try {
      const res = await api.devices.pushTemplates(sn, employee.user_id)
      showToast(`${res.templates_pushed} template(s) pushed to ${sn}`)
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setBusyDevice((b) => ({ ...b, [sn]: null }))
    }
  }

  async function handleEnroll(e) {
    e.preventDefault()
    if (!enrollDeviceSn) return
    setEnrolling(true)
    try {
      await api.devices.enrollUser(enrollDeviceSn, employee.user_id, enrollFingerId)
      showToast(`Enrollment started — ask the person to scan their finger on the device`)
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setEnrolling(false)
    }
  }

  async function handleDeleteTemplate(fingerId) {
    // Need a device the user is enrolled on to run the SDK delete
    const sn = enrolledDevices?.[0]?.device_sn
    if (!sn) {
      showToast('Employee must be enrolled on at least one device to delete a template', 'error')
      return
    }
    setBusyTemplate((b) => ({ ...b, [fingerId]: true }))
    try {
      await api.devices.deleteTemplate(sn, employee.user_id, fingerId)
      showToast(`Finger ${fingerId} template deleted`)
      reload()
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setBusyTemplate((b) => ({ ...b, [fingerId]: false }))
    }
  }

  return (
    <div className="flex-1 overflow-y-auto p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="w-12 h-12 rounded-full bg-blue-100 flex items-center justify-center text-blue-600 font-semibold text-lg mb-3">
          {employee.name.charAt(0).toUpperCase()}
        </div>
        <h2 className="text-lg font-semibold text-gray-900">{employee.name}</h2>
        <p className="text-sm text-gray-400 font-mono">{employee.user_id}</p>
      </div>

      {/* Profile */}
      <Section title="Profile">
        <div className="bg-gray-50 rounded-lg px-4 divide-y divide-gray-100">
          {[
            ['Name', employee.name],
            ['User ID', <span key="uid" className="font-mono text-xs">{employee.user_id}</span>],
            ['Card', employee.card && employee.card !== '0' ? employee.card : '—'],
            ['Privilege', <PrivilegeBadge key="priv" privilege={employee.privilege} />],
            ['Added', new Date(employee.created_at).toLocaleDateString()],
          ].map(([label, value]) => (
            <div key={label} className="flex justify-between items-center py-2.5 text-sm">
              <span className="text-gray-500">{label}</span>
              <span className="text-gray-900">{value}</span>
            </div>
          ))}
        </div>
      </Section>

      {/* Enrolled Devices */}
      <Section title="Enrolled Devices">
        {enrolledDevices === null ? (
          <p className="text-sm text-gray-400">Loading…</p>
        ) : (
          <>
            {enrolledDevices.length === 0 ? (
              <p className="text-sm text-gray-400 mb-3">Not enrolled on any device.</p>
            ) : (
              <div className="space-y-2 mb-3">
                {enrolledDevices.map((d) => {
                  const busy = busyDevice[d.device_sn]
                  const deviceName = allDevices.find((x) => x.serial_number === d.device_sn)?.name
                  return (
                    <div
                      key={d.device_sn}
                      className="bg-gray-50 rounded-lg px-3 py-2.5 flex items-center gap-2 text-sm"
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-gray-800 font-medium truncate">{deviceName || d.device_sn}</p>
                        <p className="text-xs text-gray-400 font-mono">UID {d.uid}</p>
                      </div>
                      {templates && templates.length > 0 && (
                        <button
                          onClick={() => handlePushTemplates(d.device_sn)}
                          disabled={!!busy}
                          className="text-xs text-blue-600 hover:text-blue-800 px-2 py-1 rounded hover:bg-blue-50 disabled:opacity-40 transition-colors whitespace-nowrap"
                        >
                          {busy === 'templates' ? 'Pushing…' : 'Push Templates'}
                        </button>
                      )}
                      <button
                        onClick={() => handleRemoveFromDevice(d.device_sn)}
                        disabled={!!busy}
                        className="text-xs text-red-500 hover:text-red-700 px-2 py-1 rounded hover:bg-red-50 disabled:opacity-40 transition-colors"
                      >
                        {busy === 'removing' ? 'Removing…' : 'Remove'}
                      </button>
                    </div>
                  )
                })}
              </div>
            )}

            {/* Push to a new device */}
            {unenrolledDevices.length > 0 && (
              <form onSubmit={handlePushToDevice} className="flex gap-2">
                <select
                  value={pushDeviceSn}
                  onChange={(e) => setPushDeviceSn(e.target.value)}
                  className="input flex-1 text-sm"
                >
                  <option value="">Select device to enroll…</option>
                  {unenrolledDevices.map((d) => (
                    <option key={d.serial_number} value={d.serial_number}>
                      {d.name || d.serial_number}
                    </option>
                  ))}
                </select>
                <button
                  type="submit"
                  disabled={!pushDeviceSn || pushing}
                  className="bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap"
                >
                  {pushing ? 'Pushing…' : 'Push to Device'}
                </button>
              </form>
            )}
          </>
        )}
      </Section>

      {/* Fingerprint Templates */}
      <Section title="Fingerprint Templates">
        {templates === null ? (
          <p className="text-sm text-gray-400">Loading…</p>
        ) : (
          <>
            {templates.length === 0 ? (
              <p className="text-sm text-gray-400 mb-3">No templates stored.</p>
            ) : (
              <div className="space-y-2 mb-3">
                {templates.map((t) => (
                  <div
                    key={t.finger_id}
                    className="bg-gray-50 rounded-lg px-3 py-2.5 flex items-center gap-2 text-sm"
                  >
                    <div className="flex-1">
                      <p className="text-gray-800 font-medium">
                        {FINGER_NAMES[t.finger_id] || `Finger ${t.finger_id}`}
                      </p>
                      <p className="text-xs text-gray-400">from {t.source_device_sn}</p>
                    </div>
                    <span
                      className={`text-xs px-1.5 py-0.5 rounded-full ${
                        t.valid ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-400'
                      }`}
                    >
                      {t.valid ? 'Valid' : 'Invalid'}
                    </span>
                    <button
                      onClick={() => handleDeleteTemplate(t.finger_id)}
                      disabled={busyTemplate[t.finger_id]}
                      className="text-xs text-red-500 hover:text-red-700 px-2 py-1 rounded hover:bg-red-50 disabled:opacity-40 transition-colors"
                    >
                      {busyTemplate[t.finger_id] ? '…' : 'Delete'}
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Live enroll */}
            {enrolledDevices && enrolledDevices.length > 0 && (
              <form onSubmit={handleEnroll} className="flex gap-2">
                <select
                  value={enrollDeviceSn}
                  onChange={(e) => setEnrollDeviceSn(e.target.value)}
                  className="input flex-1 min-w-0 text-sm"
                >
                  <option value="">Select device…</option>
                  {enrolledDevices.map((d) => {
                    const name = allDevices.find((x) => x.serial_number === d.device_sn)?.name
                    return (
                      <option key={d.device_sn} value={d.device_sn}>
                        {name || d.device_sn}
                      </option>
                    )
                  })}
                </select>
                <select
                  value={enrollFingerId}
                  onChange={(e) => setEnrollFingerId(Number(e.target.value))}
                  className="input w-32 text-sm"
                >
                  {FINGER_NAMES.map((name, i) => (
                    <option key={i} value={i}>{name}</option>
                  ))}
                </select>
                <button
                  type="submit"
                  disabled={!enrollDeviceSn || enrolling}
                  className="bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap"
                >
                  {enrolling ? 'Starting…' : 'Enroll'}
                </button>
              </form>
            )}
          </>
        )}
      </Section>

      {toast && (
        <Toast
          message={toast.message}
          type={toast.type}
          onDismiss={() => setToast(null)}
        />
      )}
    </div>
  )
}

export default function Employees() {
  const [employees, setEmployees] = useState([])
  const [allDevices, setAllDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    Promise.all([api.employees.list(), api.devices.list()])
      .then(([emps, devs]) => {
        setEmployees(emps)
        setAllDevices(devs)
      })
      .finally(() => setLoading(false))
  }, [])

  const filtered = employees.filter(
    (e) =>
      e.name.toLowerCase().includes(search.toLowerCase()) ||
      e.user_id.includes(search)
  )

  return (
    <div
      className="bg-white rounded-xl border border-gray-200 overflow-hidden flex"
      style={{ height: 'calc(100vh - 13rem)' }}
    >
      {/* Sidebar */}
      <div className="w-72 flex-shrink-0 border-r border-gray-200 flex flex-col">
        <div className="p-3 border-b border-gray-100">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search employees…"
            className="input w-full text-sm"
          />
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <p className="text-sm text-gray-400 text-center py-8">Loading…</p>
          ) : filtered.length === 0 ? (
            <p className="text-sm text-gray-400 text-center py-8">No results.</p>
          ) : (
            filtered.map((emp) => (
              <button
                key={emp.user_id}
                onClick={() => setSelected(emp)}
                className={`w-full text-left px-4 py-3 border-b border-gray-100 last:border-0 hover:bg-gray-50 transition-colors ${
                  selected?.user_id === emp.user_id
                    ? 'bg-blue-50 border-l-2 border-l-blue-500'
                    : ''
                }`}
              >
                <p className="text-sm font-medium text-gray-900 truncate">{emp.name}</p>
                <p className="text-xs text-gray-400 font-mono mt-0.5">{emp.user_id}</p>
              </button>
            ))
          )}
        </div>

        <div className="px-4 py-2 border-t border-gray-100 text-xs text-gray-400">
          {employees.length} employee{employees.length !== 1 ? 's' : ''}
        </div>
      </div>

      {/* Detail panel */}
      <DetailPanel employee={selected} allDevices={allDevices} />
    </div>
  )
}
