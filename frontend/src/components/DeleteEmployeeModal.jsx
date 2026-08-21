import { useState } from 'react'

/**
 * Removing a person from the system entirely (E14). Its own modal, matching
 * the DeviceTimezoneModal / DeviceProtocolModal precedent for a consequential
 * action that deserves more than a one-line window.confirm().
 *
 * Two things this text must say plainly, because getting either wrong is
 * exactly the failure this unit exists to prevent:
 *
 * - What survives: attendance history. Punches are historical fact, already
 *   pushed to the operator's HRM, and deleting them would rewrite payroll
 *   history.
 * - What is NOT necessarily final: if a device still holds this pin (should
 *   not happen — the server refuses the delete while it does — but a device
 *   can hold a pin the server was never told about), a later sync will
 *   re-create this employee. That is E1/E9 doing their job, not a bug, but
 *   an operator who thinks "delete" means "gone forever" needs to hear it
 *   before they click, not after.
 */
export default function DeleteEmployeeModal({ employee, onConfirm, onClose }) {
  const [error, setError] = useState('')
  const [deleting, setDeleting] = useState(false)

  const displayName = employee?.name || employee?.user_id || ''

  async function handleConfirm() {
    setError('')
    setDeleting(true)
    try {
      await onConfirm()
    } catch (err) {
      setError(err.message)
      setDeleting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40" />

      <div className="relative bg-white rounded-2xl shadow-xl w-full max-w-md mx-4 p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold text-gray-900">Delete employee</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            ✕
          </button>
        </div>

        <p className="text-sm text-gray-700 mb-4">
          Remove <span className="font-medium">{displayName}</span>{' '}
          <span className="font-mono text-xs text-gray-500">({employee?.user_id})</span> from
          the system.
        </p>

        <div className="space-y-2 mb-4">
          <div className="text-xs text-red-800 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
            <span className="font-semibold">Removed:</span> the enrolment and credential
            records — device links, captured face and fingerprint templates, and photos.
          </div>
          <div className="text-xs text-gray-700 bg-gray-50 border border-gray-200 rounded-lg px-3 py-2">
            <span className="font-semibold">Kept:</span> this person's attendance history.
            Punches already happened and have already reached the HRM — deleting them here
            would rewrite payroll history, so nothing here ever touches attendance.
          </div>
          <div className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
            This is not necessarily final: if a device still reports this PIN, a later sync
            will re-create this employee record from what the terminal actually holds — that
            is correct behaviour, not a bug.
          </div>
        </div>

        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-4">
            {error}
          </p>
        )}

        <div className="flex gap-3 pt-1">
          <button
            type="button"
            onClick={onClose}
            className="flex-1 border border-gray-300 text-gray-700 hover:bg-gray-50 text-sm font-medium py-2 rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            disabled={deleting}
            className="flex-1 bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
          >
            {deleting ? 'Deleting…' : 'Delete employee'}
          </button>
        </div>
      </div>
    </div>
  )
}
