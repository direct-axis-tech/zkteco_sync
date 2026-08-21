import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import RevocationCard from '../components/RevocationCard'
import DeleteEmployeeModal from '../components/DeleteEmployeeModal'

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

// A revocation, as opposed to a push. Everywhere else in this app a queued
// command means "not there yet"; here it means "still able to open that
// door", so it is pulled out of the ordinary queue list and shown separately
// and louder. Matching the wire text is deliberate — it is the same string
// the server queued, not a status this page could get out of step with.
const isRevocationCommand = (command) =>
  /^DATA DELETE (user|userauthorize)\s+Pin=/i.test(String(command || ''))

// A terminal may enrol somebody with no name at all — every record in the
// BioFace A1 capture arrived as `name=`. The ingest stores that as an empty
// string rather than inventing a plausible-looking name, so the PIN is what
// there is to show. Attendance.jsx already falls back the same way.
const displayName = (e) => (e && e.name) || e?.user_id || ''

const FINGER_NAMES = [
  'Left Little', 'Left Ring', 'Left Middle', 'Left Index', 'Left Thumb',
  'Right Thumb', 'Right Index', 'Right Middle', 'Right Ring', 'Right Little',
]

// The face photo a terminal uploaded, if any — a real <img>, not a data:
// URI (CSP's default-src 'self' covers a same-origin request; a data: URI
// would need img-src loosened, which buys nothing here). The list JSON
// never carries these bytes; each row's img tag fetches and caches its own
// copy from GET /employees/{id}/photo, and a 404 falls back to initials
// exactly the way the detail header always rendered before this existed.
function Avatar({ employee, size = 'md' }) {
  const [failed, setFailed] = useState(false)
  const initial = displayName(employee).charAt(0).toUpperCase() || '?'
  const dims = size === 'sm' ? 'w-8 h-8 text-xs' : 'w-12 h-12 text-lg'

  if (failed || !employee?.user_id) {
    return (
      <div
        className={`${dims} rounded-full bg-blue-100 flex items-center justify-center text-blue-600 font-semibold flex-shrink-0`}
      >
        {initial}
      </div>
    )
  }

  return (
    <img
      key={employee.user_id}
      src={api.employees.photoUrl(employee.user_id)}
      alt=""
      onError={() => setFailed(true)}
      className={`${dims} rounded-full object-cover flex-shrink-0 bg-gray-100`}
    />
  )
}

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
  // A `warn` toast is a successful request reporting an unwelcome truth — the
  // revocation was accepted but the door has not been told. It stays up
  // noticeably longer than a routine confirmation, and it is not red, because
  // red here would read as "the request failed" when it did not.
  const linger = type === 'warn' ? 9000 : 3500
  useEffect(() => {
    const t = setTimeout(onDismiss, linger)
    return () => clearTimeout(t)
  }, [onDismiss, linger])
  return (
    <div
      className={`fixed bottom-6 right-6 max-w-md px-4 py-3 rounded-lg shadow-lg text-sm font-medium text-white z-50 ${
        type === 'error'
          ? 'bg-red-600'
          : type === 'warn'
          ? 'bg-amber-600'
          : 'bg-gray-900'
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

function DetailPanel({ employee, allDevices, onEdit, onDeleted, isAdmin }) {
  const [enrolledDevices, setEnrolledDevices] = useState(null)
  const [templates, setTemplates] = useState(null)
  const [biometrics, setBiometrics] = useState(null)
  const [queued, setQueued] = useState([])
  const [revocationGroups, setRevocationGroups] = useState([])
  const [refused, setRefused] = useState([])
  const [toast, setToast] = useState(null)
  const [showDeleteModal, setShowDeleteModal] = useState(false)

  // Push to device
  const [pushDeviceSn, setPushDeviceSn] = useState('')
  const [pushing, setPushing] = useState(false)

  // Copy a captured biometric to another door
  const [bioDeviceSn, setBioDeviceSn] = useState('')
  const [pushingBio, setPushingBio] = useState(false)

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
    setBiometrics(null)
    api.employees.getDevices(employee.user_id).then(setEnrolledDevices).catch(() => setEnrolledDevices([]))
    api.employees.getTemplates(employee.user_id).then(setTemplates).catch(() => setTemplates([]))
    api.employees.getBiometrics(employee.user_id).then(setBiometrics).catch(() => setBiometrics([]))

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

    // One entry per revocation still outstanding for this person — grouped
    // server-side (E13) by (device_sn, pin), not re-derived here from the
    // two `DATA DELETE` commands that carry it out. That is what keeps this
    // panel from ever showing two "Cancel" buttons for one revocation.
    Promise.all(
      queueDevices.map((d) =>
        api.devices.listRevocations(d.serial_number, employee.user_id).catch(() => [])
      )
    ).then((lists) => setRevocationGroups(lists.flat()))

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

  // The outbox split in two, because the two halves mean opposite things. A
  // queued push is somebody not on a door yet; a queued delete is somebody
  // still on a door they should be off. Only the second is a hazard, so only
  // the second gets the loud treatment — and it is grouped server-side
  // (E13), one card per revocation rather than one per `DATA DELETE`.
  const pushesQueued = queued.filter((r) => !isRevocationCommand(r.command))
  // Which doors this person is being revoked from but has not been yet — used
  // to change what the Enrolled Devices row offers, so "Remove" cannot be
  // clicked twice and read as though the first one landed.
  const revokingSns = new Set(revocationGroups.map((g) => g.device_sn))
  // Doors where this person may still get in despite a revocation being on
  // the books. Read straight off `still_open` — the server's answer, itself
  // read off `device_employees` rather than either command's state. Absence
  // of a pending command is not evidence of success; the link is. Getting
  // that wrong put a reassuring "the terminal has confirmed this person's
  // removal" directly above a red "ACCESS NOT REVOKED" during E8's browser
  // check.
  const blockingSns = new Set(
    revocationGroups.filter((g) => g.still_open).map((g) => g.device_sn)
  )

  const enrolledSns = new Set((enrolledDevices || []).map((d) => d.device_sn))
  const unenrolledDevices = allDevices.filter((d) => !enrolledSns.has(d.serial_number))
  // An access-control terminal is provisioned over the command queue, so the
  // button must not promise something synchronous.
  const pushIsQueued =
    allDevices.find((d) => d.serial_number === pushDeviceSn)?.protocol === 'acc'
  // Same distinction for the biometric copy, plus the rule that decides which
  // terminals are worth offering: a template is never sent back to the device
  // that captured it, so a door that already holds every one of them has
  // nothing to receive.
  const bioIsQueued =
    allDevices.find((d) => d.serial_number === bioDeviceSn)?.protocol === 'acc'
  const sendableTo = (sn) =>
    (biometrics || []).filter((t) => t.source_device_sn !== sn).length

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

  // Removing somebody from a door is the one action in this panel whose
  // queued state is dangerous rather than merely incomplete, so it is the one
  // place the toast is not allowed to round "queued" up to "done".
  async function handleRemoveFromDevice(sn) {
    setBusyDevice((b) => ({ ...b, [sn]: 'removing' }))
    try {
      const res = await api.devices.removeUser(sn, employee.user_id)
      if (res?.status === 'queued') {
        showToast(
          res.message ||
            `Revocation queued for ${sn} — NOT yet confirmed at the door`,
          'warn'
        )
      } else if (res?.status === 'withdrawn') {
        showToast(res.message || `Undelivered push to ${sn} withdrawn`)
      } else {
        showToast(`Removed from ${sn} — the device confirmed it`)
      }
      reload()
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setBusyDevice((b) => ({ ...b, [sn]: null }))
    }
  }

  // RevocationCard owns the request and its own busy state — this only
  // reacts to the outcome. Calls E8's revocation-level DELETE, which cancels
  // BOTH `DATA DELETE` commands atomically; there is no per-command cancel
  // in this panel to accidentally leave half a revocation behind.
  function handleRevocationCancelled(res) {
    showToast(res?.message || 'Revocation cancelled')
    reload()
  }

  function handleRevocationCancelError(err) {
    showToast(err.message, 'error')
  }

  // One function for both transports, because the endpoint routes on the
  // device's protocol and the two outcomes are genuinely different: an SDK
  // push has written the terminal by the time it returns, an access-control
  // terminal has not even been told yet.
  async function handlePushTemplates(sn) {
    setBusyDevice((b) => ({ ...b, [sn]: 'templates' }))
    try {
      const res = await api.devices.pushTemplates(sn, employee.user_id)
      if (res?.status === 'queued') {
        showToast(res.message || `Queued for ${sn} — not delivered yet`)
      } else {
        showToast(`${res.templates_pushed} template(s) written to ${sn}`)
      }
      reload()
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setBusyDevice((b) => ({ ...b, [sn]: null }))
    }
  }

  async function handlePushBiometrics(e) {
    e.preventDefault()
    if (!bioDeviceSn) return
    setPushingBio(true)
    try {
      const res = await api.devices.pushTemplates(bioDeviceSn, employee.user_id)
      if (res?.status === 'queued') {
        showToast(res.message || `Queued for ${bioDeviceSn} — not delivered yet`)
      } else {
        showToast(`${res.templates_pushed} template(s) written to ${bioDeviceSn}`)
      }
      setBioDeviceSn('')
      reload()
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setPushingBio(false)
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

  // Refused (409) while any device_employees link exists — the server names
  // the doors in its error, which the modal surfaces verbatim rather than
  // paraphrasing. On success the employee is gone from this server; the
  // parent removes it from the sidebar and clears the selection.
  async function handleDeleteConfirmed() {
    const res = await api.employees.delete(employee.user_id)
    setShowDeleteModal(false)
    showToast(res?.message || `${employee.user_id} deleted`)
    onDeleted(employee.user_id)
  }

  async function handleDeleteTemplate(fingerId) {
    // Needs a device the user is enrolled on to run the SDK delete — and
    // specifically an *attendance* one. The PUSH protocol has no confirmed
    // command for deleting a single biometric on an access-control terminal
    // (the vendor's own SDK command set has none at all), so the server
    // refuses that with a 501 rather than guessing at a shape. Said here too,
    // so the operator is told what to do instead of watching a request fail.
    const sn = (enrolledDevices || [])
      .map((d) => allDevices.find((x) => x.serial_number === d.device_sn))
      .find((d) => d && (d.protocol || 'att') !== 'acc')?.serial_number
    if (!sn) {
      showToast(
        (enrolledDevices || []).length
          ? 'This person is only on access-control terminals, which have no ' +
            'command for deleting one biometric. Remove them from the door ' +
            'instead — that is what removes their templates.'
          : 'Employee must be enrolled on at least one device to delete a template',
        'error'
      )
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
        <div className="mb-3">
          <Avatar employee={employee} />
        </div>
        <h2 className="text-lg font-semibold text-gray-900">{displayName(employee)}</h2>
        <p className="text-sm text-gray-400 font-mono">{employee.user_id}</p>
      </div>

      {/* Profile */}
      <Section
        title="Profile"
        action={
          isAdmin && (
            <div className="flex gap-1">
              <button
                onClick={() => onEdit(employee)}
                className="text-xs text-blue-600 hover:text-blue-800 px-2 py-1 rounded hover:bg-blue-50 transition-colors"
              >
                Edit
              </button>
              <button
                onClick={() => setShowDeleteModal(true)}
                className="text-xs text-red-500 hover:text-red-700 px-2 py-1 rounded hover:bg-red-50 transition-colors"
              >
                Delete
              </button>
            </div>
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

      {/* Revoked in the system, not yet at the door.

          This is the section this whole unit exists for, and it is separate
          from "Queued for delivery" below on purpose. Everywhere else a
          queued command means somebody cannot get in *yet* — harmless, and
          the queue's patience with an offline terminal is the feature that
          recovered a weekend of missed punches. A queued revocation is the
          opposite: it means somebody who should have lost access still has
          it, at a physical door, and the door says nothing. So it is pulled
          out, coloured as the hazard it is, timed, and it says plainly that
          the person can still get in. */}
      {revocationGroups.length > 0 && (
        <Section
          title={
            blockingSns.size > 0
              ? 'Revoked in the system — not yet confirmed at the door'
              : 'Revoked — finishing up at the door'
          }
        >
          <div
            className={`border-2 rounded-lg p-3 ${
              blockingSns.size > 0
                ? 'border-red-300 bg-red-50'
                : 'border-amber-200 bg-amber-50'
            }`}
          >
            <p
              className={`text-xs font-semibold mb-2 ${
                blockingSns.size > 0 ? 'text-red-800' : 'text-amber-800'
              }`}
            >
              {blockingSns.size > 0 ? (
                <>
                  This person can still open the door
                  {blockingSns.size > 1 ? 's' : ''} below. The removal has been
                  queued but the terminal has not collected and confirmed it yet
                  — if it is offline, it will not until it comes back.
                </>
              ) : (
                <>
                  The terminal has confirmed this person's removal, so they can
                  no longer be recognised there. What is left below is the
                  separate door-permission record being cleared as well.
                </>
              )}
            </p>
            {/* One card per revocation (E13) — grouped server-side by
                (device_sn, pin), not one per `DATA DELETE` command. Cancel
                is offered only while the revocation could still be called
                off entirely: once the terminal has confirmed the user
                delete the person is already gone, and "let them keep this
                door" would be an offer this button cannot honour — putting
                them back is a fresh push, not a cancel. */}
            <div className="space-y-2">
              {revocationGroups.map((group) => {
                const deviceName =
                  allDevices.find((x) => x.serial_number === group.device_sn)?.name
                return (
                  <RevocationCard
                    key={`${group.device_sn}:${group.user_id}`}
                    group={group}
                    title={deviceName || group.device_sn}
                    cancelLabel={
                      isAdmin && group.still_open
                        ? 'Cancel revocation — let them keep this door'
                        : null
                    }
                    onCancelled={handleRevocationCancelled}
                    onError={handleRevocationCancelError}
                  />
                )
              })}
            </div>
          </div>
        </Section>
      )}

      {/* Queued, not delivered. An access-control terminal is never dialled:
          it collects its commands on its own schedule, so this section is the
          honest state between "pushed" and "on the device". */}
      {pushesQueued.length > 0 && (
        <Section title="Queued for delivery">
          <p className="text-xs text-gray-400 mb-2">
            Not on the device yet. Each terminal collects one command per poll
            (about every 10 seconds) and confirms it afterwards.
          </p>
          <div className="space-y-2">
            {pushesQueued.map((row) => {
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

      {/* What the device refused — and what was withdrawn before it could
          reach one. Both belong here: a biometric that never arrived is the
          state the operator most needs to see, because the person will simply
          be unrecognised at that door and nothing else will say so. */}
      {refused.length > 0 && (
        <Section title="Refused or not delivered">
          <div className="space-y-2">
            {refused.map((row) => {
              const deviceName =
                allDevices.find((x) => x.serial_number === row.device_sn)?.name
              const isDoorPermission = row.command.startsWith('DATA UPDATE userauthorize')
              const isBiometric = row.command.startsWith('DATA UPDATE BIODATA')
              const isUserDelete = /^DATA DELETE user\s+Pin=/i.test(row.command)
              const isAuthorizeDelete = row.command.startsWith('DATA DELETE userauthorize')
              // No return code means nobody refused it: the server gave up on
              // it, or withdrew it because what it depended on failed. Saying
              // "the device refused this" would point the operator at the
              // wrong end of the wire.
              const withdrawn = row.return_code == null
              // A revocation that did not land is the most serious thing this
              // panel can show, and it is worth shouting about: the operator
              // asked for somebody's access to be taken away, and it was not.
              // Cancelled-on-purpose is not that, so it is told apart by the
              // reason the server recorded rather than lumped in.
              const cancelled = /cancelled by /.test(row.last_error || '')
              const failedRevocation = isUserDelete && !cancelled
              // The device answered with a code this system cannot read (E11).
              // It is NOT a refusal — this firmware has returned such a code on
              // commands that demonstrably worked — so nothing below may say the
              // terminal refused anything. It is equally not a success, which is
              // why an unconfirmed revocation still shows as ACCESS NOT REVOKED:
              // we did not confirm it, and that is precisely what that says.
              const unconfirmed = row.verdict === 'unconfirmed'
              return (
                <div
                  key={row.id}
                  className={`rounded-lg px-3 py-2.5 text-sm ${
                    failedRevocation ? 'bg-red-100 border-2 border-red-400' : 'bg-red-50'
                  }`}
                >
                  <p className="text-gray-800 font-medium truncate">
                    {deviceName || row.device_sn}
                  </p>
                  <p className="text-xs text-red-700 mt-1">
                    {failedRevocation
                      ? 'ACCESS NOT REVOKED. This terminal never confirmed the ' +
                        'removal, so this person may still be able to open this ' +
                        'door. Check the device directly. ' +
                        (unconfirmed
                          ? 'The terminal did answer, with a code this system ' +
                            'cannot read — that is not a refusal and not a ' +
                            'confirmation. '
                          : '') +
                        (row.last_error || '')
                      : isAuthorizeDelete && !cancelled
                      ? 'The terminal did not remove the door permission record. ' +
                        'Harmless if the user record itself was removed above — ' +
                        'the person is gone either way — but worth checking if ' +
                        'it was not.'
                      : withdrawn
                      ? row.last_error ||
                        'Never delivered — the server gave up on this command.'
                      : unconfirmed
                      ? 'The terminal answered with a code this system cannot ' +
                        'read, so this was neither confirmed nor refused — it ' +
                        'may have worked. Check the device before assuming ' +
                        'either way, or send it again.'
                      : isDoorPermission
                      ? 'The door permission was refused. This person can be recognised by the terminal and will still not be let through.'
                      : isBiometric
                      ? 'The terminal refused this biometric. The person is not enrolled at this door and must enrol there in person, or be pushed again.'
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
                  // Still listed as enrolled, because the terminal has not
                  // confirmed otherwise — that is exactly what this row means
                  // and it must keep meaning it. What changes is that the row
                  // says a revocation is in flight, so nobody reads a stale
                  // "enrolled" as "the Remove click did nothing".
                  const revoking = revokingSns.has(d.device_sn)
                  return (
                    <div
                      key={d.device_sn}
                      className={`rounded-lg px-3 py-2.5 flex items-center gap-2 text-sm ${
                        revoking ? 'bg-red-50 border border-red-200' : 'bg-gray-50'
                      }`}
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-gray-800 font-medium truncate">{deviceName || d.device_sn}</p>
                        {revoking ? (
                          <p className="text-xs text-red-700 font-medium">
                            Removal queued — still open at this door
                          </p>
                        ) : (
                          <p className="text-xs text-gray-400 font-mono">UID {d.uid}</p>
                        )}
                      </div>
                      {templates && templates.length > 0 && !revoking && (
                        <button
                          onClick={() => handlePushTemplates(d.device_sn)}
                          disabled={!!busy}
                          className="text-xs text-blue-600 hover:text-blue-800 px-2 py-1 rounded hover:bg-blue-50 disabled:opacity-40 transition-colors whitespace-nowrap"
                        >
                          {busy === 'templates' ? 'Pushing…' : 'Push Templates'}
                        </button>
                      )}
                      {revoking ? (
                        <span className="text-xs text-red-600 font-semibold px-2 py-1 whitespace-nowrap">
                          Revoking…
                        </span>
                      ) : (
                        <button
                          onClick={() => handleRemoveFromDevice(d.device_sn)}
                          disabled={!!busy}
                          className="text-xs text-red-500 hover:text-red-700 px-2 py-1 rounded hover:bg-red-50 disabled:opacity-40 transition-colors"
                        >
                          {busy === 'removing' ? 'Removing…' : 'Remove'}
                        </button>
                      )}
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

      {/* Biometrics captured at a terminal, and the control that copies one
          to another door. This is the "enrol once, work everywhere" half of
          the workflow: the person walked up to one terminal, registered a
          face or a finger there, and the device uploaded it here. Sending it
          onward is what saves them walking to every other door.

          `type` is shown as the number the device sent. The protocol
          documents an enumeration and 9 has been seen in the field for a
          visible-light face, but nothing in this application branches on it,
          so nothing here translates it either — it is the device's data,
          presented as data. */}
      <Section title="Captured Biometrics">
        {biometrics === null ? (
          <p className="text-sm text-gray-400">Loading…</p>
        ) : biometrics.length === 0 ? (
          <p className="text-sm text-gray-400">
            Nothing captured yet. The person enrols a face or finger at a
            terminal and the device uploads it here by itself.
          </p>
        ) : (
          <>
            <div className="space-y-2 mb-3">
              {biometrics.map((t) => {
                const sourceName = allDevices.find(
                  (x) => x.serial_number === t.source_device_sn
                )?.name
                return (
                  <div
                    key={t.id}
                    className="bg-gray-50 rounded-lg px-3 py-2.5 flex items-center gap-2 text-sm"
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-gray-800 font-medium">
                        Type {t.type} · No {t.no}
                      </p>
                      <p className="text-xs text-gray-400 truncate">
                        captured at {sourceName || t.source_device_sn} ·{' '}
                        {t.tmp_bytes} bytes
                      </p>
                    </div>
                    <span
                      className={`text-xs px-1.5 py-0.5 rounded-full ${
                        t.valid ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-400'
                      }`}
                    >
                      {t.valid ? 'Valid' : 'Invalid'}
                    </span>
                  </div>
                )
              })}
            </div>

            {isAdmin && allDevices.length > 0 && (
              <form onSubmit={handlePushBiometrics} className="flex gap-2">
                <select
                  value={bioDeviceSn}
                  onChange={(e) => setBioDeviceSn(e.target.value)}
                  className="input flex-1 min-w-0 text-sm"
                >
                  <option value="">Copy to another door…</option>
                  {allDevices.map((d) => {
                    const count = sendableTo(d.serial_number)
                    return (
                      <option
                        key={d.serial_number}
                        value={d.serial_number}
                        disabled={count === 0}
                      >
                        {d.name || d.serial_number}
                        {count === 0 ? ' — captured here' : ` — ${count}`}
                      </option>
                    )
                  })}
                </select>
                <button
                  type="submit"
                  disabled={!bioDeviceSn || pushingBio}
                  className="bg-blue-600 hover:bg-blue-700 disabled:opacity-40 text-white text-xs font-medium px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap"
                >
                  {pushingBio
                    ? bioIsQueued
                      ? 'Queueing…'
                      : 'Pushing…'
                    : bioIsQueued
                    ? 'Queue for Device'
                    : 'Push to Device'}
                </button>
              </form>
            )}
            <p className="text-xs text-gray-400 mt-2">
              A template is never sent back to the terminal that captured it.
              {bioIsQueued
                ? ' This terminal is queued, not written: the person and each template are one command per poll, so a face plus a finger is roughly half a minute, and nothing is delivered until the device collects it.'
                : ''}
            </p>
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

      {showDeleteModal && (
        <DeleteEmployeeModal
          employee={employee}
          onConfirm={handleDeleteConfirmed}
          onClose={() => setShowDeleteModal(false)}
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

  function handleDeleted(userId) {
    setEmployees((list) => list.filter((e) => e.user_id !== userId))
    // Delayed rather than immediate: the confirmation toast lives inside
    // DetailPanel, and clearing the selection right away would unmount it
    // along with the panel before the operator can read it.
    setTimeout(() => {
      setSelected((sel) => (sel?.user_id === userId ? null : sel))
    }, 2000)
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
                className={`w-full text-left px-4 py-3 border-b border-gray-100 last:border-0 hover:bg-gray-50 transition-colors flex items-center gap-3 ${
                  selected?.user_id === emp.user_id
                    ? 'bg-blue-50 border-l-2 border-l-blue-500'
                    : ''
                }`}
              >
                <Avatar employee={emp} size="sm" />
                <div className="min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">{displayName(emp)}</p>
                  <p className="text-xs text-gray-400 font-mono mt-0.5">{emp.user_id}</p>
                </div>
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
          onDeleted={handleDeleted}
        />
      )}
    </div>
  )
}
