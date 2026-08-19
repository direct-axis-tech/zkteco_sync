import { useState } from 'react'
import { api } from '../api'
import Drawer from './Drawer'

// Pins a device to the addresses it is allowed to push from. Optional and off
// by default: sites on a dynamic IP cannot use it. Where a site does have a
// static address this is the only control that stops someone who has learned
// the serial number from forging attendance for it.
export default function DeviceSecurityDrawer({ device, onClose, onSaved, showToast }) {
  const [enabled, setEnabled] = useState(device.ip_check_enabled)
  const [cidrs, setCidrs] = useState(device.allowed_cidrs || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function save(payload) {
    setError('')
    setSaving(true)
    try {
      await api.devices.update(device.serial_number, payload)
      showToast('IP allowlist updated')
      onSaved()
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  function handleSubmit(e) {
    e.preventDefault()
    save({ ip_check_enabled: enabled, allowed_cidrs: cidrs })
  }

  function handleClear() {
    save({ ip_check_enabled: false, allowed_cidrs: '' })
  }

  return (
    <Drawer title="IP Allowlist" onClose={onClose}>
      <p className="text-sm text-gray-500 mb-4">
        Restrict <span className="font-mono text-gray-700">{device.serial_number}</span> to
        pushing attendance only from these addresses. Leave the check off for sites on a
        dynamic IP.
      </p>

      <div className="mb-4 text-sm">
        <p className="text-gray-500 mb-1">Last push seen from</p>
        <p className="font-mono text-gray-900">{device.last_ip || '—'}</p>
        {device.last_ip && (
          <button
            type="button"
            onClick={() => setCidrs(cidrs ? `${cidrs}, ${device.last_ip}` : device.last_ip)}
            className="mt-1 text-xs text-blue-600 hover:text-blue-700"
          >
            Add this address
          </button>
        )}
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Allowed CIDRs
          </label>
          <textarea
            rows={3}
            value={cidrs}
            onChange={(e) => setCidrs(e.target.value)}
            placeholder="203.0.113.0/24, 198.51.100.7"
            className="input w-full font-mono text-xs"
          />
          <p className="mt-1 text-xs text-gray-400">
            Comma separated. A bare address means that address only.
          </p>
        </div>

        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          Enforce this allowlist
        </label>

        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
            {error}
          </p>
        )}

        <div className="flex gap-2">
          <button
            type="submit"
            disabled={saving}
            className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
          <button
            type="button"
            onClick={handleClear}
            disabled={saving}
            className="px-4 border border-gray-200 hover:bg-gray-50 disabled:opacity-50 text-gray-700 text-sm font-medium py-2 rounded-lg transition-colors"
          >
            Clear
          </button>
        </div>
      </form>
    </Drawer>
  )
}
