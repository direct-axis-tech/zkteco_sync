import { useState } from 'react'
import { api } from '../api'
import Drawer from './Drawer'

export default function WriteLcdDrawer({ device, onClose, showToast }) {
  const [line, setLine] = useState(1)
  const [text, setText] = useState('')
  const [saving, setSaving] = useState(false)
  const [clearing, setClearing] = useState(false)
  const [error, setError] = useState('')

  async function handleWrite(e) {
    e.preventDefault()
    setError('')
    setSaving(true)
    try {
      await api.devices.writeLcd(device.serial_number, line, text)
      showToast('LCD updated')
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  async function handleClear() {
    setError('')
    setClearing(true)
    try {
      await api.devices.clearLcd(device.serial_number)
      showToast('LCD cleared')
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setClearing(false)
    }
  }

  return (
    <Drawer title="Write LCD" onClose={onClose}>
      <form onSubmit={handleWrite} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Line</label>
          <input
            type="number"
            min={1}
            max={6}
            required
            value={line}
            onChange={(e) => setLine(Number(e.target.value))}
            className="input w-full"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Text</label>
          <input
            type="text"
            required
            maxLength={24}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Welcome"
            className="input w-full"
          />
        </div>

        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
            {error}
          </p>
        )}

        <div className="flex gap-3">
          <button
            type="button"
            onClick={handleClear}
            disabled={clearing}
            className="flex-1 border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50 text-sm font-medium py-2 rounded-lg transition-colors"
          >
            {clearing ? 'Clearing…' : 'Clear LCD'}
          </button>
          <button
            type="submit"
            disabled={saving}
            className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
          >
            {saving ? 'Writing…' : 'Write'}
          </button>
        </div>
      </form>
    </Drawer>
  )
}
