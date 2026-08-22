import { useState, useEffect } from 'react'
import { api } from '../api'
import Drawer from './Drawer'

// The bulk endpoint names a deliberate skip in `errors` alongside real
// failures ("employee not found in DB") because it has no separate channel
// for "correctly did nothing to this person." E3's only skip reason is an
// outstanding, unconfirmed revocation on this device, and its message always
// contains the word "revocation" — see push_users_bulk. That is the one
// signal this drawer has to keep a deliberate skip from reading like a bug.
const isSkipReason = (line) => /revocation/i.test(line)

export default function DeviceUsersDrawer({ device, onClose, showToast }) {
  const [allEmployees, setAllEmployees] = useState([])
  const [enrolledIds, setEnrolledIds] = useState(new Set())
  const [selected, setSelected] = useState(new Set())
  const [loading, setLoading] = useState(true)
  const [pushing, setPushing] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [pushErrors, setPushErrors] = useState([])
  const [skipped, setSkipped] = useState([])

  useEffect(() => {
    Promise.all([
      api.employees.list(),
      api.devices.listUsers(device.serial_number),
    ])
      .then(([employees, enrolled]) => {
        setAllEmployees(employees)
        const ids = new Set(enrolled.map((e) => e.user_id))
        setEnrolledIds(ids)
        setSelected(new Set(ids))
      })
      .catch((e) => setLoadError(e.message))
      .finally(() => setLoading(false))
  }, [device.serial_number])

  function toggle(user_id) {
    setSelected((prev) => {
      const next = new Set(prev)
      next.has(user_id) ? next.delete(user_id) : next.add(user_id)
      return next
    })
  }

  function toggleAll() {
    if (selected.size === allEmployees.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(allEmployees.map((e) => e.user_id)))
    }
  }

  async function handlePush() {
    if (selected.size === 0) return
    setPushing(true)
    setPushErrors([])
    setSkipped([])
    try {
      const result = await api.devices.pushBulk(device.serial_number, [...selected])
      const errors = result.errors || []
      const skips = errors.filter(isSkipReason)
      const realErrors = errors.filter((e) => !isSkipReason(e))
      setSkipped(skips)
      setPushErrors(realErrors)

      // `transport` only appears on the adms_queue branch (see
      // push_users_bulk) — its absence is how the SDK branch, where
      // "pushed" is already true, is told apart from it. Use the server's
      // own wording rather than re-deriving "queued" vs "pushed" here: it
      // already carries the honest command count and drain estimate.
      if (result.pushed.length > 0) {
        if (result.transport === 'adms_queue') {
          showToast(`${result.message} Track real delivery in the Commands drawer.`)
        } else {
          showToast(`${result.pushed.length} user(s) pushed to ${device.name || device.serial_number}`)
        }
      }

      if (skips.length === 0 && realErrors.length === 0) {
        onClose()
      }
    } catch (e) {
      setPushErrors([e.message])
    } finally {
      setPushing(false)
    }
  }

  const allChecked = allEmployees.length > 0 && selected.size === allEmployees.length
  const someChecked = selected.size > 0 && selected.size < allEmployees.length

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
          <p className="text-xs text-gray-500 mb-3">
            Select employees to push to{' '}
            <span className="font-medium">{device.name || device.serial_number}</span>.
            Pre-checked employees are already enrolled.
          </p>

          {skipped.length > 0 && (
            <div className="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 mb-4">
              <p className="font-medium mb-1">Skipped on purpose — not pushed</p>
              <p className="whitespace-pre-wrap">{skipped.join('\n')}</p>
            </div>
          )}

          {pushErrors.length > 0 && (
            <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-4 whitespace-pre-wrap">
              {pushErrors.join('\n')}
            </p>
          )}

          <div className="flex items-center gap-2 mb-2 px-2">
            <input
              type="checkbox"
              id="select-all"
              checked={allChecked}
              ref={(el) => { if (el) el.indeterminate = someChecked }}
              onChange={toggleAll}
              className="rounded"
            />
            <label htmlFor="select-all" className="text-sm text-gray-600 cursor-pointer select-none">
              {allChecked ? 'Deselect all' : 'Select all'} ({allEmployees.length})
            </label>
          </div>

          <div className="border border-gray-200 rounded-lg divide-y divide-gray-100 mb-4 max-h-96 overflow-y-auto">
            {allEmployees.length === 0 && (
              <p className="text-sm text-gray-400 text-center py-6">No employees in database.</p>
            )}
            {allEmployees.map((emp) => {
              const isEnrolled = enrolledIds.has(emp.user_id)
              const isSelected = selected.has(emp.user_id)
              return (
                <label
                  key={emp.user_id}
                  className="flex items-center gap-3 px-3 py-2.5 hover:bg-gray-50 cursor-pointer"
                >
                  <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => toggle(emp.user_id)}
                    className="rounded flex-shrink-0"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 truncate">{emp.name}</p>
                    <p className="text-xs text-gray-400 font-mono">{emp.user_id}</p>
                  </div>
                  {isEnrolled && (
                    <span className="text-xs text-green-600 bg-green-50 border border-green-200 px-2 py-0.5 rounded-full flex-shrink-0">
                      Enrolled
                    </span>
                  )}
                </label>
              )
            })}
          </div>

          <button
            onClick={handlePush}
            disabled={pushing || selected.size === 0}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
          >
            {pushing
              ? 'Pushing…'
              : `Push ${selected.size} user${selected.size !== 1 ? 's' : ''} to device`}
          </button>
        </>
      )}
    </Drawer>
  )
}
