import { useState, useEffect } from 'react'
import { api } from '../api'
import Drawer from './Drawer'

export default function DeviceUsersDrawer({ device, onClose, showToast }) {
  const [allEmployees, setAllEmployees] = useState([])
  const [enrolledIds, setEnrolledIds] = useState(new Set())
  const [selected, setSelected] = useState(new Set())
  const [loading, setLoading] = useState(true)
  const [pushing, setPushing] = useState(false)
  const [error, setError] = useState('')

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
      .catch((e) => setError(e.message))
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
    setError('')
    try {
      const result = await api.devices.pushBulk(device.serial_number, [...selected])
      if (result.errors?.length) {
        setError(result.errors.join('\n'))
      } else {
        showToast(`${result.pushed.length} user(s) pushed to ${device.name || device.serial_number}`)
        onClose()
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setPushing(false)
    }
  }

  const allChecked = allEmployees.length > 0 && selected.size === allEmployees.length
  const someChecked = selected.size > 0 && selected.size < allEmployees.length

  return (
    <Drawer title="Device Users" onClose={onClose}>
      {loading && <p className="text-sm text-gray-400 text-center py-8">Loading…</p>}

      {!loading && error && (
        <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-4 whitespace-pre-wrap">
          {error}
        </p>
      )}

      {!loading && !error && (
        <>
          <p className="text-xs text-gray-500 mb-3">
            Select employees to push to{' '}
            <span className="font-medium">{device.name || device.serial_number}</span>.
            Pre-checked employees are already enrolled.
          </p>

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
