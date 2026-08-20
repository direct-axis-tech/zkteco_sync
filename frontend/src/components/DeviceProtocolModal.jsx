import { useState } from 'react'

const PROTOCOLS = [
  { value: 'att', label: 'Attendance PUSH (att)' },
  { value: 'acc', label: 'Security PUSH (acc, access control)' },
]

/**
 * Correcting a device's protocol is its own deliberate action, not a field on
 * the device form — matching DeviceTimezoneModal's precedent. It gets its own
 * modal and its own endpoint (PATCH /devices/{sn}/protocol), because a manual
 * change here pins the value against the automatic DeviceType/ATTLOG
 * classification in adms.py until the device itself proves otherwise.
 */
export default function DeviceProtocolModal({ device, onSave, onClose }) {
  const [protocol, setProtocol] = useState(device.protocol || 'att')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const changed = protocol !== (device.protocol || 'att')

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setSaving(true)
    try {
      await onSave(protocol)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop — not clickable */}
      <div className="absolute inset-0 bg-black/40" />

      {/* Modal */}
      <div className="relative bg-white rounded-2xl shadow-xl w-full max-w-md mx-4 p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold text-gray-900">Change Protocol</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            ✕
          </button>
        </div>

        <p className="text-sm text-gray-500 mb-4">
          <span className="font-medium text-gray-700">{device.name || device.serial_number}</span>{' '}
          normally has this set automatically from what the device announces. Use this only
          when a terminal has just been switched between cloud and local server modes.
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Protocol
              <span className="ml-1.5 text-xs font-normal text-gray-400">
                currently {device.protocol || 'att'}
                {device.protocol_pinned ? ' (manually pinned)' : ' (automatic)'}
              </span>
            </label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              className="input w-full text-sm"
              data-testid="device-protocol-select"
            >
              {PROTOCOLS.map((p) => (
                <option key={p.value} value={p.value}>{p.label}</option>
              ))}
            </select>
          </div>

          <div className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2">
            Saving pins this value: the server stops changing it automatically until the
            device itself sends evidence it speaks a different protocol (a fresh handshake,
            an attendance push, or a registration call), at which point the pin is cleared
            and the correction is recorded in the audit log — never silent.
          </div>

          {error && (
            <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
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
              type="submit"
              disabled={saving || !changed}
              className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
            >
              {saving ? 'Saving…' : 'Update'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
