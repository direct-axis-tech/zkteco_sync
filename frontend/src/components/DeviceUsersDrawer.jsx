import { useState, useEffect, useMemo } from 'react'
import { api } from '../api'
import Drawer from './Drawer'

// The bulk endpoint names a deliberate skip in `errors` alongside real
// failures ("employee not found in DB") because it has no separate channel
// for "correctly did nothing to this person." E3's only skip reason is an
// outstanding, unconfirmed revocation on this device, and its message always
// contains the word "revocation" — see push_users_bulk. That is the one
// signal this drawer has to keep a deliberate skip from reading like a bug.
const isSkipReason = (line) => /revocation/i.test(line)

// Two pushes, one tab each. Each tab keeps its own ticks, and nothing is
// ticked on opening: what gets pushed is only what the operator picked, not
// everybody the device already holds.
const TABS = {
  users: {
    label: 'Users',
    push: (sn, ids) => api.devices.pushBulk(sn, ids),
    button: (n) => `Push ${n} user${n !== 1 ? 's' : ''} to device`,
    busy: 'Pushing…',
    hint: 'Sends each person’s record — name, card, privilege and stored keypad password.',
    defaultFilter: 'missing',
  },
  templates: {
    label: 'Templates',
    push: (sn, ids) => api.devices.pushTemplatesBulk(sn, ids),
    button: (n) => `Push templates of ${n} user${n !== 1 ? 's' : ''}`,
    busy: 'Pushing templates…',
    hint:
      'Sends the fingerprints (and, on access-control doors, faces) this app has stored. ' +
      'A person the device does not hold yet is sent ahead of their templates.',
    defaultFilter: 'sendable',
  },
}

// Each filter is a predicate over one row: { emp, onDevice, sendable }.
const FILTERS = {
  users: [
    ['missing', 'Not on device', (r) => !r.onDevice],
    ['enrolled', 'On device', (r) => r.onDevice],
    ['all', 'All', () => true],
  ],
  templates: [
    ['sendable', 'Has templates to send', (r) => r.sendable > 0],
    ['missing', 'Not on device', (r) => !r.onDevice],
    ['enrolled', 'On device', (r) => r.onDevice],
    ['all', 'All', () => true],
  ],
}

function emptyOutcome() {
  return { errors: [], skipped: [], withheld: [] }
}

export default function DeviceUsersDrawer({ device, onClose, showToast }) {
  const sn = device.serial_number
  const [allEmployees, setAllEmployees] = useState([])
  const [enrolledIds, setEnrolledIds] = useState(new Set())
  // user_id -> { sendable, withheld }, from GET /devices/{sn}/templates/sendable.
  const [templateCounts, setTemplateCounts] = useState(new Map())
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')

  const [tab, setTab] = useState('users')
  const [filter, setFilter] = useState({ users: TABS.users.defaultFilter, templates: TABS.templates.defaultFilter })
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState({ users: new Set(), templates: new Set() })
  const [pushing, setPushing] = useState(false)
  const [outcome, setOutcome] = useState(emptyOutcome())

  useEffect(() => {
    Promise.all([
      api.employees.list(),
      api.devices.listUsers(sn),
      api.devices.sendableTemplates(sn),
    ])
      .then(([employees, enrolled, sendable]) => {
        setAllEmployees(employees)
        setEnrolledIds(new Set(enrolled.map((e) => e.user_id)))
        setTemplateCounts(new Map(sendable.map((r) => [r.user_id, r])))
      })
      .catch((e) => setLoadError(e.message))
      .finally(() => setLoading(false))
  }, [sn])

  const rows = useMemo(
    () =>
      allEmployees.map((emp) => ({
        emp,
        onDevice: enrolledIds.has(emp.user_id),
        sendable: templateCounts.get(emp.user_id)?.sendable || 0,
        withheldTemplates: templateCounts.get(emp.user_id)?.withheld || 0,
      })),
    [allEmployees, enrolledIds, templateCounts]
  )

  const filters = FILTERS[tab]
  const activeFilter = filters.find(([key]) => key === filter[tab]) || filters[0]
  const query = search.trim().toLowerCase()
  const visible = rows.filter(
    (r) =>
      activeFilter[2](r) &&
      (!query ||
        r.emp.user_id.toLowerCase().includes(query) ||
        (r.emp.name || '').toLowerCase().includes(query))
  )

  const picked = selected[tab]
  const visiblePicked = visible.filter((r) => picked.has(r.emp.user_id)).length
  const hiddenPicked = picked.size - visiblePicked
  const allVisibleChecked = visible.length > 0 && visiblePicked === visible.length

  function switchTab(next) {
    setTab(next)
    setOutcome(emptyOutcome())
  }

  function setPicked(update) {
    setSelected((prev) => ({ ...prev, [tab]: update(new Set(prev[tab])) }))
  }

  function toggle(userId) {
    setPicked((next) => {
      next.has(userId) ? next.delete(userId) : next.add(userId)
      return next
    })
  }

  // Ticks or unticks only what the current filter and search show, so
  // "Not on device" + Select all is exactly the people the device lacks.
  function toggleVisible() {
    setPicked((next) => {
      visible.forEach((r) =>
        allVisibleChecked ? next.delete(r.emp.user_id) : next.add(r.emp.user_id)
      )
      return next
    })
  }

  async function handlePush() {
    if (picked.size === 0) return
    setPushing(true)
    setOutcome(emptyOutcome())
    try {
      const result = await TABS[tab].push(sn, [...picked])
      const errors = result.errors || []
      // The template push files its deliberate skips (nothing captured, the
      // device's own originals, a revocation) in `skipped`; the user push
      // still mixes them into `errors`.
      const next = {
        skipped: (result.skipped || []).concat(errors.filter(isSkipReason)),
        errors: errors.filter((e) => !isSkipReason(e)),
        // Privileged people the push sent as ordinary users, because this
        // device holds no password, fingerprint or face for them.
        withheld: result.privilege_withheld || [],
      }
      setOutcome(next)

      // `transport` only appears on the adms_queue branch (see
      // push_users_bulk) — its absence is how the SDK branch, where
      // "pushed" is already true, is told apart from it. Use the server's
      // own wording rather than re-deriving "queued" vs "pushed" here: it
      // already carries the honest command count and drain estimate.
      if (result.pushed.length > 0) {
        if (result.transport === 'adms_queue') {
          showToast(`${result.message} Track real delivery in the Commands drawer.`)
        } else {
          showToast(`${result.pushed.length} user(s) pushed to ${device.name || sn}`)
        }
      }

      if (!next.skipped.length && !next.errors.length && !next.withheld.length) {
        onClose()
      }
    } catch (e) {
      setOutcome({ ...emptyOutcome(), errors: [e.message] })
    } finally {
      setPushing(false)
    }
  }

  const count = (pred) => rows.filter(pred).length

  return (
    <Drawer title="Device Users" onClose={onClose}>
      {loading && <p className="text-sm text-gray-400 text-center py-8">Loading…</p>}

      {!loading && loadError && (
        <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-4 whitespace-pre-wrap">
          {loadError}
        </p>
      )}

      {!loading && !loadError && (
        <>
          <div className="flex gap-1 border-b border-gray-200 mb-3 -mt-1">
            {Object.entries(TABS).map(([key, t]) => (
              <button
                key={key}
                onClick={() => switchTab(key)}
                className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                  tab === key
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-800'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          <p className="text-xs text-gray-500 mb-3">
            Push to <span className="font-medium">{device.name || sn}</span>.{' '}
            {TABS[tab].hint}
          </p>

          {outcome.skipped.length > 0 && (
            <div className="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-4">
              <p className="font-medium mb-1">Skipped on purpose — not pushed</p>
              <p className="whitespace-pre-wrap">{outcome.skipped.join('\n')}</p>
            </div>
          )}

          {outcome.withheld.length > 0 && (
            <div className="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-4">
              <p className="font-medium mb-1">Pushed as ordinary users, not administrators</p>
              <p className="mb-1">{outcome.withheld.join(', ')}</p>
              <p className="text-xs">
                This device holds no keypad password, fingerprint or face for
                them, so as administrators they would lock its menu. Their
                privilege is unchanged — set a keypad password or push their
                templates, then push them again.
              </p>
            </div>
          )}

          {outcome.errors.length > 0 && (
            <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-4 whitespace-pre-wrap">
              {outcome.errors.join('\n')}
            </p>
          )}

          <div className="flex flex-wrap gap-1.5 mb-3">
            {filters.map(([key, label, pred]) => (
              <button
                key={key}
                onClick={() => setFilter((f) => ({ ...f, [tab]: key }))}
                className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                  activeFilter[0] === key
                    ? 'bg-blue-600 border-blue-600 text-white'
                    : 'border-gray-300 text-gray-600 hover:bg-gray-50'
                }`}
              >
                {label} ({count(pred)})
              </button>
            ))}
          </div>

          <input
            className="input w-full text-sm mb-3"
            placeholder="Search by name or user ID"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />

          <div className="flex items-center gap-2 mb-2 px-2">
            <input
              type="checkbox"
              id="select-visible"
              checked={allVisibleChecked}
              ref={(el) => { if (el) el.indeterminate = visiblePicked > 0 && !allVisibleChecked }}
              onChange={toggleVisible}
              disabled={visible.length === 0}
              className="rounded"
            />
            <label htmlFor="select-visible" className="text-sm text-gray-600 cursor-pointer select-none">
              {allVisibleChecked ? 'Deselect' : 'Select'} all shown ({visible.length})
            </label>
            {hiddenPicked > 0 && (
              <span className="ml-auto text-xs text-gray-400">
                +{hiddenPicked} ticked, not shown
              </span>
            )}
          </div>

          <div className="border border-gray-200 rounded-lg divide-y divide-gray-100 mb-4 max-h-96 overflow-y-auto">
            {visible.length === 0 && (
              <p className="text-sm text-gray-400 text-center py-6">
                {allEmployees.length === 0 ? 'No employees in database.' : 'Nobody matches this filter.'}
              </p>
            )}
            {visible.map((r) => (
              <label
                key={r.emp.user_id}
                className="flex items-center gap-3 px-3 py-2.5 hover:bg-gray-50 cursor-pointer"
              >
                <input
                  type="checkbox"
                  checked={picked.has(r.emp.user_id)}
                  onChange={() => toggle(r.emp.user_id)}
                  className="rounded flex-shrink-0"
                />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 truncate">{r.emp.name || r.emp.user_id}</p>
                  <p className="text-xs text-gray-400 font-mono">{r.emp.user_id}</p>
                </div>
                {tab === 'templates' && (
                  <span className="text-xs text-gray-500 flex-shrink-0">
                    {r.sendable > 0
                      ? `${r.sendable} template${r.sendable !== 1 ? 's' : ''}`
                      : r.withheldTemplates > 0
                      ? 'device has its own'
                      : 'none stored'}
                  </span>
                )}
                {r.onDevice && (
                  <span className="text-xs text-green-600 bg-green-50 border border-green-200 px-2 py-0.5 rounded-full flex-shrink-0">
                    On device
                  </span>
                )}
              </label>
            ))}
          </div>

          <button
            onClick={handlePush}
            disabled={pushing || picked.size === 0}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
          >
            {pushing ? TABS[tab].busy : TABS[tab].button(picked.size)}
          </button>
        </>
      )}
    </Drawer>
  )
}
