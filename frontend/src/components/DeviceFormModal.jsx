import { useState, useEffect } from 'react'

const EMPTY_FORM = { serial_number: '', ip_address: '', port: 4370, name: '' }

export default function DeviceFormModal({ mode, device, onSave, onClose }) {
  const isEdit = mode === 'edit'
  const [form, setForm] = useState(EMPTY_FORM)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (isEdit && device) {
      setForm({
        serial_number: device.serial_number,
        ip_address: device.ip_address,
        port: device.port,
        name: device.name || '',
      })
    }
  }, [isEdit, device])

  function set(field, value) {
    setForm((f) => ({ ...f, [field]: value }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setSaving(true)
    try {
      const payload = isEdit
        ? { ip_address: form.ip_address, port: Number(form.port), name: form.name || null }
        : { ...form, port: Number(form.port), name: form.name || null }
      await onSave(payload)
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
          <h2 className="text-lg font-semibold text-gray-900">
            {isEdit ? 'Edit Device' : 'Add Device'}
          </h2>
          <button
            type="button"
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label="Serial Number" required>
            <input
              type="text"
              required
              disabled={isEdit}
              value={form.serial_number}
              onChange={(e) => set('serial_number', e.target.value)}
              placeholder="CQZ7230961348"
              className="input disabled:bg-gray-100 disabled:text-gray-400"
            />
          </Field>

          <Field label="IP Address" required>
            <input
              type="text"
              required
              value={form.ip_address}
              onChange={(e) => set('ip_address', e.target.value)}
              placeholder="192.168.0.67"
              className="input"
            />
          </Field>

          <Field label="Port" required>
            <input
              type="number"
              required
              value={form.port}
              onChange={(e) => set('port', e.target.value)}
              className="input"
            />
          </Field>

          <Field label="Name">
            <input
              type="text"
              value={form.name}
              onChange={(e) => set('name', e.target.value)}
              placeholder="Door Access (optional)"
              className="input"
            />
          </Field>

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
              disabled={saving}
              className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
            >
              {saving ? 'Saving…' : isEdit ? 'Save Changes' : 'Add Device'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function Field({ label, required, children }) {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">
        {label}
        {required && <span className="text-red-500 ml-0.5">*</span>}
      </label>
      {children}
    </div>
  )
}
