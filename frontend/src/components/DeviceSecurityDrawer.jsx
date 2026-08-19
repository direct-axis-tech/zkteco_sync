import { useState } from 'react'
import { api } from '../api'
import Drawer from './Drawer'

// Device-level security controls: source-IP pinning and the SDK comm key.
// The IP allowlist is optional and off by default (some sites have dynamic
// IPs); where a site does have a static address it is the only control that
// stops someone who has learned the serial number from forging attendance
// for it. The comm key is the only authentication on TCP 4370 and is
// handled write-only — the server never tells the browser what it is, only
// whether one is set.
export default function DeviceSecurityDrawer({ device, onClose, onSaved, showToast }) {
  const [enabled, setEnabled] = useState(device.ip_check_enabled)
  const [cidrs, setCidrs] = useState(device.allowed_cidrs || '')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const [commKeySet, setCommKeySet] = useState(device.comm_key_set)
  const [commKeyEditing, setCommKeyEditing] = useState(false)
  const [commKeyInput, setCommKeyInput] = useState('')
  const [commKeySaving, setCommKeySaving] = useState(false)
  const [commKeyError, setCommKeyError] = useState('')

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

  async function saveCommKey(value) {
    setCommKeyError('')
    setCommKeySaving(true)
    try {
      const updated = await api.devices.update(device.serial_number, { comm_key: value })
      setCommKeySet(updated.comm_key_set)
      setCommKeyEditing(false)
      setCommKeyInput('')
      showToast(value === 0 ? 'Comm key cleared' : 'Comm key set')
    } catch (err) {
      setCommKeyError(err.message)
    } finally {
      setCommKeySaving(false)
    }
  }

  function handleCommKeySave(e) {
    e.preventDefault()
    const value = Number(commKeyInput)
    if (commKeyInput.trim() === '' || !Number.isInteger(value) || value < 0) {
      setCommKeyError('Enter a whole number (0 or greater)')
      return
    }
    saveCommKey(value)
  }

  return (
    <Drawer title="Device Security" onClose={onClose}>
      <div className="mb-5 pb-5 border-b border-gray-100">
        <label className="block text-sm font-medium text-gray-700 mb-1">Comm Key</label>
        <p className="text-xs text-gray-400 mb-2">
          Authenticates the server to the device on TCP 4370. Once set it is never shown
          again — only whether one is configured.
        </p>

        <div className="flex items-center gap-2">
          <span
            className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
              commKeySet ? 'bg-blue-50 text-blue-700' : 'bg-gray-100 text-gray-500'
            }`}
          >
            {commKeySet ? 'Set' : 'Not set'}
          </span>
          {!commKeyEditing && (
            <button
              type="button"
              onClick={() => setCommKeyEditing(true)}
              className="text-xs text-blue-600 hover:text-blue-700"
            >
              {commKeySet ? 'Change' : 'Set key'}
            </button>
          )}
          {commKeySet && !commKeyEditing && (
            <button
              type="button"
              disabled={commKeySaving}
              onClick={() => saveCommKey(0)}
              className="text-xs text-red-600 hover:text-red-700 disabled:opacity-50"
            >
              Clear
            </button>
          )}
        </div>

        {commKeyEditing && (
          <form onSubmit={handleCommKeySave} className="flex items-center gap-2 mt-2">
            <input
              type="password"
              inputMode="numeric"
              autoComplete="new-password"
              value={commKeyInput}
              onChange={(e) => setCommKeyInput(e.target.value)}
              placeholder="New comm key"
              className="input flex-1 font-mono text-xs"
            />
            <button
              type="submit"
              disabled={commKeySaving}
              className="text-xs bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium px-3 py-1.5 rounded-lg transition-colors"
            >
              {commKeySaving ? 'Saving…' : 'Save'}
            </button>
            <button
              type="button"
              onClick={() => { setCommKeyEditing(false); setCommKeyInput(''); setCommKeyError('') }}
              className="text-xs text-gray-500 hover:text-gray-700"
            >
              Cancel
            </button>
          </form>
        )}

        {commKeyError && <p className="text-xs text-red-600 mt-1">{commKeyError}</p>}
      </div>

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
