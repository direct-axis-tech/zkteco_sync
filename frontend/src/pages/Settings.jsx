import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'

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

const AUDIT_PAGE_SIZE = 20

function AuditLog() {
  const [filters, setFilters] = useState({ actor: '', action: '', from_date: '', to_date: '' })
  const [offset, setOffset] = useState(0)
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)

  const load = useCallback((currentFilters, currentOffset) => {
    setLoading(true)
    api.audit
      .list({ ...currentFilters, limit: AUDIT_PAGE_SIZE, offset: currentOffset })
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    load(filters, offset)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [offset])

  function applyFilters(e) {
    e.preventDefault()
    setOffset(0)
    load(filters, 0)
  }

  const items = data?.items || []
  const total = data?.total || 0

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden mt-6">
      <div className="px-5 py-4 border-b border-gray-200">
        <p className="font-medium text-gray-900">Audit Log</p>
        <p className="text-xs text-gray-400 mt-0.5">
          Privileged and physical actions, attributed to an actor and source IP.
        </p>
      </div>

      <form onSubmit={applyFilters} className="px-5 py-4 border-b border-gray-100 grid grid-cols-2 sm:grid-cols-5 gap-3">
        <input
          type="text"
          placeholder="Actor"
          value={filters.actor}
          onChange={(e) => setFilters((f) => ({ ...f, actor: e.target.value }))}
          className="input text-sm"
        />
        <input
          type="text"
          placeholder="Action"
          value={filters.action}
          onChange={(e) => setFilters((f) => ({ ...f, action: e.target.value }))}
          className="input text-sm"
        />
        <input
          type="date"
          aria-label="From date"
          value={filters.from_date}
          onChange={(e) => setFilters((f) => ({ ...f, from_date: e.target.value }))}
          className="input text-sm"
        />
        <input
          type="date"
          aria-label="To date"
          value={filters.to_date}
          onChange={(e) => setFilters((f) => ({ ...f, to_date: e.target.value }))}
          className="input text-sm"
        />
        <button
          type="submit"
          className="bg-gray-900 hover:bg-gray-800 text-white text-xs font-medium py-2 rounded-lg transition-colors"
        >
          Filter
        </button>
      </form>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-gray-400 border-b border-gray-100">
              <th className="px-5 py-2 font-medium">Time</th>
              <th className="px-5 py-2 font-medium">Actor</th>
              <th className="px-5 py-2 font-medium">Action</th>
              <th className="px-5 py-2 font-medium">Target</th>
              <th className="px-5 py-2 font-medium">IP</th>
              <th className="px-5 py-2 font-medium">Detail</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id} className="border-b border-gray-50 last:border-0">
                <td className="px-5 py-2 text-xs text-gray-500 whitespace-nowrap">
                  {new Date(row.created_at).toLocaleString()}
                </td>
                <td className="px-5 py-2 text-xs text-gray-900">{row.actor}</td>
                <td className="px-5 py-2 text-xs font-mono text-gray-700">{row.action}</td>
                <td className="px-5 py-2 text-xs text-gray-500 font-mono">{row.target || '—'}</td>
                <td className="px-5 py-2 text-xs text-gray-500 font-mono">{row.ip || '—'}</td>
                <td className="px-5 py-2 text-xs text-gray-500 break-all">{row.detail || '—'}</td>
              </tr>
            ))}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={6} className="px-5 py-6 text-center text-xs text-gray-400">
                  No matching entries
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between px-5 py-3 border-t border-gray-100 text-xs text-gray-500">
        <span>{total} total</span>
        <div className="flex gap-2">
          <button
            type="button"
            disabled={offset === 0}
            onClick={() => setOffset(Math.max(0, offset - AUDIT_PAGE_SIZE))}
            className="border border-gray-300 disabled:opacity-40 text-gray-600 px-3 py-1 rounded-lg"
          >
            Prev
          </button>
          <button
            type="button"
            disabled={offset + AUDIT_PAGE_SIZE >= total}
            onClick={() => setOffset(offset + AUDIT_PAGE_SIZE)}
            className="border border-gray-300 disabled:opacity-40 text-gray-600 px-3 py-1 rounded-lg"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Settings() {
  const { user } = useAuth()
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
      // Write-only: the server never tells the browser what the secret is,
      // only whether one is set (cfg.secret_set). Blank here means "leave
      // it alone" — see handleSave.
      secret:           '',
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
      const payload = { ...form }
      // Don't send an empty secret — the backend would ignore it anyway,
      // but keep the intent explicit here too: blank means unchanged.
      if (!payload.secret) delete payload.secret
      const updated = await api.hrmSync.update(payload)
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

  const isConfigured = cfg?.endpoint && cfg?.secret_set

  return (
    <div className="max-w-4xl">
      <h1 className="text-xl font-semibold text-gray-900 mb-6">Settings</h1>

      <div className="max-w-xl bg-white rounded-xl border border-gray-200 overflow-hidden">

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

            <Field
              label="Secret Key"
              hint={cfg.secret_set ? 'leave blank to keep the current secret' : undefined}
            >
              <input
                type="password"
                autoComplete="new-password"
                value={form.secret}
                onChange={(e) => setForm((f) => ({ ...f, secret: e.target.value }))}
                placeholder={cfg.secret_set ? '••••••••' : 'Shared secret configured in server.php'}
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
            <div className="flex justify-between items-center py-2.5 border-b border-gray-100 text-sm">
              <span className="text-gray-500">Secret</span>
              <span
                className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
                  cfg.secret_set ? 'bg-blue-50 text-blue-700' : 'bg-gray-100 text-gray-500'
                }`}
              >
                {cfg.secret_set ? 'Set' : 'Not set'}
              </span>
            </div>
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

      {user?.role === 'admin' && <AuditLog />}

      {toast && (
        <Toast message={toast.message} type={toast.type} onDismiss={() => setToast(null)} />
      )}
    </div>
  )
}
