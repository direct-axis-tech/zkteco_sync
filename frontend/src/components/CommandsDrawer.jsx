import { useState } from 'react'
import { api } from '../api'
import Drawer from './Drawer'

const PRESETS = [
  { label: 'Reboot', value: 'REBOOT' },
  { label: 'Sync Time', value: 'DATE' },
  { label: 'Enable', value: 'ENABLE' },
  { label: 'Disable', value: 'DISABLE' },
]

export default function CommandsDrawer({ device, onClose, showToast }) {
  const [command, setCommand] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState('')

  async function handleSend(e) {
    e.preventDefault()
    if (!command.trim()) return
    setError('')
    setSending(true)
    try {
      await api.devices.queueCommand(device.serial_number, command.trim())
      showToast('Command queued')
      setCommand('')
    } catch (err) {
      setError(err.message)
    } finally {
      setSending(false)
    }
  }

  return (
    <Drawer title="Queue Command" onClose={onClose}>
      <p className="text-sm text-gray-500 mb-4">
        Commands are delivered to the device on its next heartbeat poll.
      </p>

      <div className="flex flex-wrap gap-2 mb-4">
        {PRESETS.map((p) => (
          <button
            key={p.value}
            type="button"
            onClick={() => setCommand(p.value)}
            className="text-xs border border-gray-300 text-gray-600 hover:bg-gray-50 px-3 py-1 rounded-full transition-colors"
          >
            {p.label}
          </button>
        ))}
      </div>

      <form onSubmit={handleSend} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Command</label>
          <input
            type="text"
            required
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            placeholder="REBOOT"
            className="input w-full font-mono"
          />
        </div>

        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={sending}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
        >
          {sending ? 'Queuing…' : 'Queue Command'}
        </button>
      </form>
    </Drawer>
  )
}
