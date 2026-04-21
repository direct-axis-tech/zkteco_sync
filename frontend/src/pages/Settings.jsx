import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'

function StatusRow({ label, value, mono }) {
  return (
    <div className="flex justify-between items-center py-2.5 border-b border-gray-100 last:border-0 text-sm">
      <span className="text-gray-500">{label}</span>
      <span className={`text-gray-900 ${mono ? 'font-mono text-xs' : ''}`}>{value ?? '—'}</span>
    </div>
  )
}

export default function Settings() {
  const [status, setStatus] = useState(null)
  const [running, setRunning] = useState(false)
  const [toast, setToast] = useState(null)

  const load = useCallback(() => {
    api.hrmSync.status().then(setStatus).catch(() => {})
  }, [])

  useEffect(() => {
    load()
    const t = setInterval(load, 15_000)
    return () => clearInterval(t)
  }, [load])

  async function handleRunNow() {
    setRunning(true)
    try {
      await api.hrmSync.run()
      setToast('Sync started — check status in a moment')
      setTimeout(load, 3000)
    } catch (err) {
      setToast(err.message)
    } finally {
      setRunning(false)
    }
  }

  function fmt(iso) {
    return iso ? new Date(iso).toLocaleString() : '—'
  }

  return (
    <div className="max-w-xl">
      <h1 className="text-xl font-semibold text-gray-900 mb-6">Settings</h1>

      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div>
            <p className="font-medium text-gray-900">HRM Attendance Sync</p>
            <p className="text-xs text-gray-400 mt-0.5">
              Pushes new attendance records to your HRM server on a schedule.
            </p>
          </div>
          {status && (
            <span
              className={`text-xs font-medium px-2.5 py-1 rounded-full ${
                status.configured
                  ? 'bg-green-100 text-green-700'
                  : 'bg-gray-100 text-gray-500'
              }`}
            >
              {status.configured ? 'Configured' : 'Not configured'}
            </span>
          )}
        </div>

        {status === null ? (
          <div className="p-6 text-sm text-gray-400">Loading…</div>
        ) : !status.configured ? (
          <div className="p-6 text-sm text-gray-500">
            <p className="mb-2">HRM sync is not configured. Add the following to your <code className="bg-gray-100 px-1 rounded">.env</code> file and restart:</p>
            <pre className="bg-gray-50 border border-gray-200 rounded-lg p-3 text-xs font-mono text-gray-700 whitespace-pre-wrap">
{`HRM_SYNC_ENDPOINT=http://hrm.server/sync_attendance/server.php
HRM_SYNC_SECRET=your-shared-secret
HRM_SYNC_LOCATION_ID=1
HRM_SYNC_INTERVAL=300
HRM_SYNC_TIMEZONE=Asia/Dubai`}
            </pre>
          </div>
        ) : (
          <div className="px-5">
            <StatusRow label="Last run" value={fmt(status.last_run_at)} />
            <StatusRow label="Last synced ID" value={status.last_synced_id} mono />
            <StatusRow label="Records pushed (last run)" value={status.records_last_push?.toLocaleString()} />
            <StatusRow label="Total records pushed" value={status.total_pushed?.toLocaleString()} />
            {status.last_error && (
              <div className="py-3 border-b border-gray-100">
                <p className="text-xs font-medium text-red-600 mb-1">Last error</p>
                <p className="text-xs text-red-500 font-mono break-all">{status.last_error}</p>
              </div>
            )}
          </div>
        )}

        {status?.configured && (
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
        <div
          className="fixed bottom-6 right-6 px-4 py-3 rounded-lg shadow-lg text-sm font-medium text-white bg-gray-900 z-50"
          onClick={() => setToast(null)}
        >
          {toast}
        </div>
      )}
    </div>
  )
}
