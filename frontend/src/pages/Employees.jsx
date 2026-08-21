import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'

const PRIVILEGE_LABELS = { 0: 'User', 2: 'Enroller', 14: 'Admin' }

// A queued command names its subject in a `Pin=` field, TAB-separated from the
// rest (§3.8). Matched field by field rather than by substring, so PIN 9001
// does not pick up the commands belonging to PIN 19001.
function commandIsAbout(command, userId) {
  return String(command || '')
    .split('\t')
    .some((field) => field.trim().replace(/^DATA \w+ \w+ /, '') === `Pin=${userId}`)
}

// What a row in the outbox actually means, in the operator's words. `pending`
// is not a failure: the device has simply not polled yet.
const COMMAND_STATE = {
  pending: 'Waiting for the device to poll',
  sent: 'Delivered — waiting for the device to confirm',
}

// A terminal may enrol somebody with no name at all — every record in the
// BioFace A1 capture arrived as `name=`. The ingest stores that as an empty
// string rather than inventing a plausible-looking name, so the PIN is what
// there is to show. Attendance.jsx already falls back the same way.
const displayName = (e) => (e && e.name) || e?.user_id || ''

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

function Field({ label, hint, children }) {
  return (
    <label className="block mb-3">
      <span className="block text-xs font-medium text-gray-500 mb-1">{label}</span>
      {children}
      {hint && <span className="block text-xs text-gray-400 mt-1">{hint}</span>}
    </label>
  )
}

// Creating a person and editing one are the same six fields, minus the PIN:
// the PIN is the key every attendance record and every biometric hangs off,
// so it is set once and never renamed.
function EmployeeForm({ employee, onDone, onCancel }) {
  const editing = !!employee
  const [form, setForm] = useState({
    user_id: employee?.user_id || '',
    name: employee?.name || '',
    card: employee && employee.card !== '0' ? employee.card : '',
    privilege: employee?.privilege ?? 0,
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  const set = (key, value) => setForm((f) => ({ ...f, [key]: value }))

  async function handleSubmit(e) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      const saved = editing
        ? await api.employees.update(employee.user_id, {
            name: form.name,
            card: form.card,
            privilege: Number(form.privilege),
          })
        : await api.employees.create({
            user_id: form.user_id.trim(),
            name: form.name,
            card: form.card,
            privilege: Number(form.privilege),
          })
      onDone(saved, editing)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <h2 className="text-lg font-semibold text-gray-900 mb-1">
        {editing ? `Edit ${displayName(employee)}` : 'New employee'}
      </h2>
      <p className="text-sm text-gray-400 mb-5">
        {editing
          ? 'Saving changes here does not update any device. Push the person again to send the new details.'
          : 'Adds the person to this server only. Push them to a device afterwards, then enrol their face or finger at that terminal.'}
      </p>

      <form onSubmit={handleSubmit} className="max-w-md">
        {!editing && (
          <Field
            label="User ID (PIN)"
            hint="The number the terminal knows this person by. Cannot be changed later."
          >
            <input
              className="input w-full text-sm"
              value={form.user_id}
              onChange={(e) => set('user_id', e.target.value)}
              required
              maxLength={24}
            />
          </Field>
        )}

        <Field label="Name" hint="Optional — a person with no name shows as their PIN.">
          <input
            className="input w-full text-sm"
            value={form.name}
            onChange={(e) => set('name', e.target.value)}
            maxLength={100}
          />
        </Field>

        <Field label="Card number" hint="Optional. Leave empty for no card.">
          <input
            className="input w-full text-sm"
            value={form.card}
            onChange={(e) => set('card', e.target.value)}
            maxLength={20}
          />
        </Field>

        <Field
          label="Privilege"
          hint="Administrator gives this person the terminal's own menus."
        >
          <select
            className="input w-full text-sm"
            value={form.privilege}
            onChange={(e) => set('privilege', e.target.value)}
          >
            <option value={0}>User</option>
            <option value={2}>Enroller</option>
            <option value={14}>Administrator</option>
          </select>
        </Field>

        {error && <p className="text-sm text-red-600 mb-3">{error}</p>}

        <div className="flex gap-2 mt-4">
          <button
            type="submit"
            disabled={saving || (!editing && !form.user_id.trim())}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
          >
            {saving ? 'Saving…' : editing ? 'Save changes' : 'Create employee'}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="text-sm text-gray-500 hover:text-gray-700 px-4 py-2 rounded-lg hover:bg-gray-50 transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </div>
  )
}

function DetailPanel({ employee, allDevices, onEdit, isAdmin }) {
  const [enrolledDevices, setEnrolledDevices] = useState(null)
  const [templates, setTemplates] = useState(null)
  const [queued, setQueued] = useState([])
  const [refused, setRefused] = useState([])
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

    // What is still owed to a device for this person. Only `acc` terminals
    // have an outbox — an SDK push is synchronous and has either happened or
    // failed by the time the call returns.
    const queueDevices = allDevices.filter((d) => d.protocol === 'acc')
    Promise.all(
      queueDevices.map((d) =>
        api.devices
          .listCommands(d.serial_number)
          .then((rows) =>
            rows
              .filter((r) => commandIsAbout(r.command, employee.user_id))
              .map((r) => ({ ...r, device_sn: d.serial_number }))
          )
          .catch(() => [])
      )
    ).then((lists) => setQueued(lists.flat()))

    // Commands the device refused. Worth its own section rather than being
    // left in the device's command history: a `user` record that landed and a
    // `userauthorize` that was refused is a person the terminal recognises,
    // lets enrol, verifies — and then will not open the door for. That is the
    // hardest state in this whole workflow to diagnose from the outside.
    Promise.all(
      queueDevices.map((d) =>
        api.devices
          .commandHistory(d.serial_number)
          .then((rows) =>
            rows
              .filter((r) => r.outcome === 'failed' && commandIsAbout(r.command, employee.user_id))
              .map((r) => ({ ...r, device_sn: d.serial_number }))
          )
          .catch(() => [])
      )
    ).then((lists) => setRefused(lists.flat()))
  }, [employee?.user_id, allDevices])

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
  // An access-control terminal is provisioned over the command queue, so the
  // button must not promise something synchronous.
  const pushIsQueued =
    allDevices.find((d) => d.serial_number === pushDeviceSn)?.protocol === 'acc'

  async function handlePushToDevice(e) {
    e.preventDefault()
    if (!pushDeviceSn) return
    setPushing(true)
    try {
      const result = await api.devices.pushUser(pushDeviceSn, employee.user_id)
      // "Queued" and "written" are different things and the difference is
      // visible to the operator, because only one of them means the device
      // has actually got the person. An access-control terminal collects its
      // commands on its next poll — about ten seconds — and confirms them
      // afterwards; claiming success here would be a guess.
      if (result?.status === 'queued') {
        showToast(result.message || `Queued for ${pushDeviceSn} — not delivered yet`)
      } else {
        showToast(`Written to ${pushDeviceSn}`)
      }
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
          {displayName(employee).charAt(0).toUpperCase()}
        </div>
        <h2 className="text-lg font-semibold text-gray-900">{displayName(employee)}</h2>
        <p className="text-sm text-gray-400 font-mono">{employee.user_id}</p>
      </div>

      {/* Profile */}
      <Section
        title="Profile"
        action={
          isAdmin && (
            <button
              onClick={() => onEdit(employee)}
              className="text-xs text-blue-600 hover:text-blue-800 px-2 py-1 rounded hover:bg-blue-50 transition-colors"
            >
              Edit
            </button>
          )
        }
      >
        <div className="bg-gray-50 rounded-lg px-4 divide-y divide-gray-100">
          {[
            ['Name', employee.name || '—'],
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

      {/* Queued, not delivered. An access-control terminal is never dialled:
          it collects its commands on its own schedule, so this section is the
          honest state between "pushed" and "on the device". */}
      {queued.length > 0 && (
        <Section title="Queued for delivery">
          <p className="text-xs text-gray-400 mb-2">
            Not on the device yet. Each terminal collects one command per poll
            (about every 10 seconds) and confirms it afterwards.
          </p>
          <div className="space-y-2">
            {queued.map((row) => {
              const deviceName =
                allDevices.find((x) => x.serial_number === row.device_sn)?.name
              return (
                <div key={row.id} className="bg-amber-50 rounded-lg px-3 py-2.5 text-sm">
                  <div className="flex items-center gap-2">
                    <p className="text-gray-800 font-medium flex-1 min-w-0 truncate">
                      {deviceName || row.device_sn}
                    </p>
                    <span className="text-xs px-1.5 py-0.5 rounded-full bg-amber-100 text-amber-700">
                      {row.status === 'sent' ? 'Awaiting confirmation' : 'Queued'}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    {COMMAND_STATE[row.status] || row.status}
                    {row.attempts > 0 && ` · attempt ${row.attempts}`}
                  </p>
                  <p className="text-xs text-gray-400 font-mono mt-1 truncate">
                    {row.command.split('\t')[0]}
                  </p>
                </div>
              )
            })}
          </div>
        </Section>
      )}

      {/* What the device refused. */}
      {refused.length > 0 && (
        <Section title="Refused by the device">
          <div className="space-y-2">
            {refused.map((row) => {
              const deviceName =
                allDevices.find((x) => x.serial_number === row.device_sn)?.name
              const isDoorPermission = row.command.startsWith('DATA UPDATE userauthorize')
              return (
                <div key={row.id} className="bg-red-50 rounded-lg px-3 py-2.5 text-sm">
                  <p className="text-gray-800 font-medium truncate">
                    {deviceName || row.device_sn}
                  </p>
                  <p className="text-xs text-red-700 mt-1">
                    {isDoorPermission
                      ? 'The door permission was refused. This person can be recognised by the terminal and will still not be let through.'
                      : 'The device refused this command.'}
                    {row.return_code != null && ` (Return=${row.return_code})`}
                  </p>
                  <p className="text-xs text-gray-400 font-mono mt-1 truncate">
                    {row.command.split('\t')[0]}
                  </p>
                </div>
              )
            })}
          </div>
        </Section>
      )}

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
                  {pushing
                    ? pushIsQueued
                      ? 'Queueing…'
                      : 'Pushing…'
                    : pushIsQueued
                    ? 'Queue for Device'
                    : 'Push to Device'}
                </button>
              </form>
            )}
            {pushIsQueued && (
              <p className="text-xs text-gray-400 mt-2">
                This terminal is queued, not written directly: it collects the
                person and their door permission on its next poll. They appear
                above once the device confirms, and can enrol a face or finger
                at the terminal from then on.
              </p>
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
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const [employees, setEmployees] = useState([])
  const [allDevices, setAllDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState(null)
  // null | 'create' | an employee being edited
  const [editing, setEditing] = useState(null)

  function handleSaved(saved, wasEditing) {
    setEmployees((list) =>
      wasEditing
        ? list.map((e) => (e.user_id === saved.user_id ? saved : e))
        : [...list, saved]
    )
    setSelected(saved)
    setEditing(null)
  }

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
      (e.name || '').toLowerCase().includes(search.toLowerCase()) ||
      e.user_id.includes(search)
  )

  return (
    <div
      className="bg-white rounded-xl border border-gray-200 overflow-hidden flex h-[calc(100vh-13rem)]"
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
          {isAdmin && (
            <button
              onClick={() => setEditing('create')}
              className="mt-2 w-full bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition-colors"
            >
              New employee
            </button>
          )}
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
                onClick={() => {
                  setSelected(emp)
                  setEditing(null)
                }}
                className={`w-full text-left px-4 py-3 border-b border-gray-100 last:border-0 hover:bg-gray-50 transition-colors ${
                  selected?.user_id === emp.user_id
                    ? 'bg-blue-50 border-l-2 border-l-blue-500'
                    : ''
                }`}
              >
                <p className="text-sm font-medium text-gray-900 truncate">{displayName(emp)}</p>
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
      {editing ? (
        <EmployeeForm
          employee={editing === 'create' ? null : editing}
          onDone={handleSaved}
          onCancel={() => setEditing(null)}
        />
      ) : (
        <DetailPanel
          employee={selected}
          allDevices={allDevices}
          isAdmin={isAdmin}
          onEdit={setEditing}
        />
      )}
    </div>
  )
}
