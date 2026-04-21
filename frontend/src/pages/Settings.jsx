import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'

function Field({ label, hint, children }) {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">
        {label}
        {hint && <span className="ml-1.5 text-xs font-normal text-gray-400">{hint}</span>}
      </label>
      {children}
    </div>
  )
}

function StatusRow({ label, value, mono, editable, onEdit }) {
  return (
    <div className="flex justify-between items-center py-2.5 border-b border-gray-100 last:border-0 text-sm">
      <span className="text-gray-500">{label}</span>
      <div className="flex items-center gap-2">
        <span className={`text-gray-900 ${mono ? 'font-mono text-xs' : ''}`}>{value ?? '—'}</span>
        {editable && (
          <button
            onClick={onEdit}
            className="text-xs text-blue-500 hover:text-blue-700 underline"
          >
            Edit
          </button>
        )}
      </div>
    </div>
  )
}

function Toast({ message, type = 'success', onDismiss }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 3500)
    return () => clearTimeout(t)
  }, [onDismiss])
  return (
    <div
      className={`fixed bottom-6 right-6 px-4 py-3 rounded-lg shadow-lg text-sm font-medium text-white z-50 ${
        type === 'error' ? 'bg-red-600' : 'bg-gray-900'
      }`}
    >
      {message}
    </div>
  )
}

export default function Settings() {
  const [cfg, setCfg] = useState(null)
  const [form, setForm] = useState(null)        // null = view mode, object = edit mode
  const [editId, setEditId] = useState(null)    // editing last_synced_id inline
  const [running, setRunning] = useState(false)
  const [saving, setSaving] = useState(false)
  const [toast, setToast] = useState(null)

  const showToast = (msg, type = 'success') => setToast({ message: msg, type })

  const load = useCallback(() => {
    api.hrmSync.status().then((data) => {
      setCfg(data)
    }).catch(() => {})
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 15_000)
    return () => clearInterval(t)
  }, [load])

  function startEdit() {
    setForm({
      endpoint:         cfg.endpoint || '',
      secret:           cfg.secret || '',
      location_id:      cfg.location_id || '1',
      interval_seconds: cfg.interval_seconds ?? 300,
      timezone:         cfg.timezone || 'UTC',
      enabled:          cfg.enabled ?? true,
    })
  }

  function cancelEdit() {
    setForm(null)
  }

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    try {
      const updated = await api.hrmSync.update(form)
      setCfg(updated)
      setForm(null)
      showToast('Configuration saved')
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setSaving(false)
    }
  }

  async function handleSaveLastId(e) {
    e.preventDefault()
    const val = parseInt(editId, 10)
    if (isNaN(val) || val < 0) return
    try {
      const updated = await api.hrmSync.update({ last_synced_id: val })
      setCfg(updated)
      setEditId(null)
      showToast('Last synced ID updated')
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handleRunNow() {
    setRunning(true)
    try {
      await api.hrmSync.run()
      showToast('Sync started')
      setTimeout(load, 3000)
    } catch (err) {
      showToast(err.message, 'error')
    } finally {
      setRunning(false)
    }
  }

  const isConfigured = cfg?.endpoint && cfg?.secret

  return (
    <div className="max-w-xl">
      <h1 className="text-xl font-semibold text-gray-900 mb-6">Settings</h1>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div>
            <p className="font-medium text-gray-900">HRM Attendance Sync</p>
            <p className="text-xs text-gray-400 mt-0.5">
              Pushes new attendance records to your HRM server on a schedule.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {cfg && (
              <span className={`text-xs font-medium px-2.5 py-1 rounded-full ${
                cfg.enabled && isConfigured
                  ? 'bg-green-100 text-green-700'
                  : isConfigured
                  ? 'bg-yellow-100 text-yellow-700'
                  : 'bg-gray-100 text-gray-500'
              }`}>
                {cfg.enabled && isConfigured ? 'Active' : isConfigured ? 'Paused' : 'Not configured'}
              </span>
            )}
            {cfg && !form && (
              <button
                onClick={startEdit}
                className="text-sm text-blue-600 hover:text-blue-800 font-medium"
              >
                Configure
              </button>
            )}
          </div>
        </div>

        {cfg === null && (
          <div className="p-6 text-sm text-gray-400">Loading…</div>
        )}

        {/* Config form */}
        {form && (
          <form onSubmit={handleSave} className="p-5 space-y-4 border-b border-gray-100">
            <Field label="Endpoint URL">
              <input
                type="url"
                value={form.endpoint}
                onChange={(e) => setForm((f) => ({ ...f, endpoint: e.target.value }))}
                placeholder="http://hrm.server/sync_attendance/server.php"
                className="input w-full text-sm"
              />
            </Field>

            <Field label="Secret Key">
              <input
                type="password"
                value={form.secret}
                onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value }))}
                placeholder="Shared secret configured in server.php"
                className="input w-full text-sm"
              />
            </Field>

            <div className="grid grid-cols-2 gap-3">
              <Field label="Location ID">
                <input
                  type="text"
                  value={form.location_id}
                  onChange={(e) => setForm((f) => ({ ...f, location_id: e.target.value }))}
                  className="input w-full text-sm"
                />
              </Field>

              <Field label="Interval" hint="seconds">
                <input
                  type="number"
                  min={60}
                  value={form.interval_seconds}
                  onChange={(e) => setForm((f) => ({ ...f, interval_seconds: Number(e.target.value) }))}
                  className="input w-full text-sm"
                />
              </Field>
            </div>

            <Field label="Timezone" hint="e.g. Asia/Dubai, UTC, America/New_York">
              <input
                type="text"
                value={form.timezone}
                onChange={(e) => setForm((f) => ({ ...f, timezone: e.target.value }))}
                className="input w-full text-sm"
              />
            </Field>

            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
                className="rounded"
              />
              <span className="text-gray-700">Enable automatic sync</span>
            </label>

            <div className="flex gap-3 pt-1">
              <button
                type="button"
                onClick={cancelEdit}
                className="flex-1 border border-gray-300 text-gray-700 hover:bg-gray-50 text-sm font-medium py-2 rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-lg transition-colors"
              >
                {saving ? 'Saving…' : 'Save'}
              </button>
            </div>
          </form>
        )}

        {/* Status */}
        {cfg && !form && (
          <div className="px-5">
            <StatusRow
              label="Last run"
              value={cfg.last_run_at
                ? new Date(cfg.last_run_at).toLocaleString(undefined, { timeZone: cfg.timezone || 'UTC' })
                : null}
            />
            <StatusRow
              label="Last synced ID"
              value={cfg.last_synced_id ?? 0}
              mono
              editable={editId === null}
              onEdit={() => setEditId(String(cfg.last_synced_id ?? 0))}
            />
            {editId !== null && (
              <form onSubmit={handleSaveLastId} className="py-3 flex gap-2 border-b border-gray-100">
                <input
                  type="number"
                  min={0}
                  value={editId}
                  onChange={(e) => setEditId(e.target.value)}
                  className="input flex-1 text-sm font-mono"
                  autoFocus
                />
                <button
                  type="submit"
                  className="bg-blue-600 text-white text-xs font-medium px-3 rounded-lg"
                >
                  Update
                </button>
                <button
                  type="button"
                  onClick={() => setEditId(null)}
                  className="border border-gray-300 text-gray-600 text-xs font-medium px-3 rounded-lg"
                >
                  Cancel
                </button>
              </form>
            )}
            <StatusRow label="Records pushed (last run)" value={cfg.records_last_push?.toLocaleString()} />
            <StatusRow label="Total records pushed" value={cfg.total_pushed?.toLocaleString()} />
            <StatusRow label="Interval" value={cfg.interval_seconds ? `${cfg.interval_seconds}s` : null} />
            <StatusRow label="Location ID" value={cfg.location_id} />
            <StatusRow label="Timezone" value={cfg.timezone} />
            {cfg.last_error && (
              <div className="py-3 border-b border-gray-100">
                <p className="text-xs font-medium text-red-600 mb-1">Last error</p>
                <p className="text-xs text-red-500 font-mono break-all">{cfg.last_error}</p>
              </div>
            )}
          </div>
        )}

        {/* Actions */}
        {cfg && !form && isConfigured && (
          <div className="px-5 py-4 border-t border-gray-100">
            <button
              onClick={handleRunNow}
              disabled={running}
              className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
            >
              {running ? 'Starting…' : 'Sync Now'}
            </button>
          </div>
        )}
      </div>

      {toast && (
        <Toast message={toast.message} type={toast.type} onDismiss={() => setToast(null)} />
      )}
    </div>
  )
}
