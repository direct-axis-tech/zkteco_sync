import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'

const PAGE_SIZE = 50

const STATUS_LABELS = {
  0: { label: 'Check In', style: 'bg-green-100 text-green-700' },
  1: { label: 'Check Out', style: 'bg-blue-100 text-blue-700' },
  2: { label: 'Break Out', style: 'bg-yellow-100 text-yellow-700' },
  3: { label: 'Break In', style: 'bg-yellow-100 text-yellow-700' },
  4: { label: 'OT In', style: 'bg-orange-100 text-orange-700' },
  5: { label: 'OT Out', style: 'bg-orange-100 text-orange-700' },
}

function StatusBadge({ status }) {
  const s = STATUS_LABELS[status] || { label: `Status ${status}`, style: 'bg-gray-100 text-gray-500' }
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium ${s.style}`}>
      {s.label}
    </span>
  )
}

export default function Attendance() {
  const [devices, setDevices] = useState([])
  const [employees, setEmployees] = useState([])
  const [filters, setFilters] = useState({
    device_sn: '',
    user_id: '',
    from_date: '',
    to_date: '',
  })
  const [rows, setRows] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.devices.list().then(setDevices).catch(() => {})
    api.employees.list().then(setEmployees).catch(() => {})
  }, [])

  const load = useCallback(async (f, p) => {
    setLoading(true)
    try {
      const params = {
        ...(f.device_sn ? { device_sn: f.device_sn } : {}),
        ...(f.user_id ? { user_id: f.user_id } : {}),
        ...(f.from_date ? { from_date: f.from_date + ':00' } : {}),
        ...(f.to_date ? { to_date: f.to_date + ':00' } : {}),
        limit: PAGE_SIZE,
        offset: p * PAGE_SIZE,
      }
      const [data, countData] = await Promise.all([
        api.attendance.list(params),
        api.attendance.count(params),
      ])
      setRows(data)
      setTotal(countData.count)
    } catch {
      setRows([])
      setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load(filters, page)
  }, [load, filters, page])

  function setFilter(key, value) {
    setFilters((f) => ({ ...f, [key]: value }))
    setPage(0)
  }

  const totalPages = Math.ceil(total / PAGE_SIZE)

  function formatTs(iso) {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    })
  }

  function employeeName(userId) {
    return employees.find((e) => e.user_id === userId)?.name || userId
  }

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-gray-900">Attendance</h1>
        <span className="text-sm text-gray-400">{total.toLocaleString()} records</span>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl border border-gray-200 p-4 mb-4 grid grid-cols-2 md:grid-cols-4 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">Device</label>
          <select
            value={filters.device_sn}
            onChange={(e) => setFilter('device_sn', e.target.value)}
            className="input w-full text-sm"
          >
            <option value="">All devices</option>
            {devices.map((d) => (
              <option key={d.serial_number} value={d.serial_number}>
                {d.name || d.serial_number}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">Employee</label>
          <select
            value={filters.user_id}
            onChange={(e) => setFilter('user_id', e.target.value)}
            className="input w-full text-sm"
          >
            <option value="">All employees</option>
            {employees.map((e) => (
              <option key={e.user_id} value={e.user_id}>
                {e.name}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">From</label>
          <input
            type="datetime-local"
            value={filters.from_date}
            onChange={(e) => setFilter('from_date', e.target.value)}
            className="input w-full text-sm"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">To</label>
          <input
            type="datetime-local"
            value={filters.to_date}
            onChange={(e) => setFilter('to_date', e.target.value)}
            className="input w-full text-sm"
          />
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-sm text-gray-400">Loading…</div>
        ) : rows.length === 0 ? (
          <div className="p-12 text-center text-sm text-gray-400">No records found.</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50">
                <th className="text-left px-4 py-3 font-medium text-gray-500">Employee</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Timestamp</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Status</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Device</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Source</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.id}
                  className="border-b border-gray-100 last:border-0 hover:bg-gray-50 transition-colors"
                >
                  <td className="px-4 py-3">
                    <p className="font-medium text-gray-900">{employeeName(row.user_id)}</p>
                    <p className="text-xs text-gray-400 font-mono">{row.user_id}</p>
                  </td>
                  <td className="px-4 py-3 text-gray-700 tabular-nums">{formatTs(row.timestamp)}</td>
                  <td className="px-4 py-3"><StatusBadge status={row.status} /></td>
                  <td className="px-4 py-3 text-gray-400 font-mono text-xs">{row.device_sn}</td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{row.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100 text-sm">
            <span className="text-gray-400">
              Page {page + 1} of {totalPages}
            </span>
            <div className="flex gap-2">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="px-3 py-1 rounded border border-gray-200 text-gray-600 hover:bg-gray-50 disabled:opacity-40 transition-colors"
              >
                ← Prev
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="px-3 py-1 rounded border border-gray-200 text-gray-600 hover:bg-gray-50 disabled:opacity-40 transition-colors"
              >
                Next →
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  )
}
