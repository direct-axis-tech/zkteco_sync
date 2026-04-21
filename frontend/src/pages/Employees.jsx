import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'

const PRIVILEGE_LABELS = {
  0: 'User',
  2: 'Enroller',
  14: 'Admin',
}

function PrivilegeBadge({ privilege }) {
  const label = PRIVILEGE_LABELS[privilege] || `Level ${privilege}`
  const style =
    privilege === 14
      ? 'bg-purple-100 text-purple-700'
      : privilege === 2
      ? 'bg-blue-100 text-blue-700'
      : 'bg-gray-100 text-gray-500'
  return (
    <span className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium ${style}`}>
      {label}
    </span>
  )
}

function Section({ title, children }) {
  return (
    <div className="mb-6">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-3">{title}</p>
      {children}
    </div>
  )
}

function DetailPanel({ employee }) {
  const [devices, setDevices] = useState(null)
  const [templates, setTemplates] = useState(null)

  useEffect(() => {
    setDevices(null)
    setTemplates(null)
    if (!employee) return
    api.employees.getDevices(employee.user_id).then(setDevices).catch(() => setDevices([]))
    api.employees.getTemplates(employee.user_id).then(setTemplates).catch(() => setTemplates([]))
  }, [employee?.user_id])

  if (!employee) {
    return (
      <div className="flex-1 flex items-center justify-center text-sm text-gray-400">
        Select an employee to view details
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="mb-6">
        <div className="w-12 h-12 rounded-full bg-blue-100 flex items-center justify-center text-blue-600 font-semibold text-lg mb-3">
          {employee.name.charAt(0).toUpperCase()}
        </div>
        <h2 className="text-lg font-semibold text-gray-900">{employee.name}</h2>
        <p className="text-sm text-gray-400 font-mono">{employee.user_id}</p>
      </div>

      <Section title="Profile">
        <div className="bg-gray-50 rounded-lg px-4 divide-y divide-gray-100">
          {[
            ['Name', employee.name],
            ['User ID', <span className="font-mono text-xs">{employee.user_id}</span>],
            ['Card', employee.card && employee.card !== '0' ? employee.card : '—'],
            ['Privilege', <PrivilegeBadge privilege={employee.privilege} />],
            ['Added', new Date(employee.created_at).toLocaleDateString()],
          ].map(([label, value]) => (
            <div key={label} className="flex justify-between items-center py-2.5 text-sm">
              <span className="text-gray-500">{label}</span>
              <span className="text-gray-900">{value}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section title="Enrolled Devices">
        {devices === null ? (
          <p className="text-sm text-gray-400">Loading…</p>
        ) : devices.length === 0 ? (
          <p className="text-sm text-gray-400">Not enrolled on any device.</p>
        ) : (
          <div className="space-y-2">
            {devices.map((d) => (
              <div
                key={d.device_sn}
                className="bg-gray-50 rounded-lg px-4 py-2.5 flex justify-between items-center text-sm"
              >
                <span className="text-gray-700 font-mono text-xs">{d.device_sn}</span>
                <span className="text-gray-400 text-xs">UID {d.uid}</span>
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title="Fingerprint Templates">
        {templates === null ? (
          <p className="text-sm text-gray-400">Loading…</p>
        ) : templates.length === 0 ? (
          <p className="text-sm text-gray-400">No templates stored.</p>
        ) : (
          <div className="space-y-2">
            {templates.map((t) => (
              <div
                key={t.finger_id}
                className="bg-gray-50 rounded-lg px-4 py-2.5 flex justify-between items-center text-sm"
              >
                <span className="text-gray-700">Finger {t.finger_id}</span>
                <div className="flex items-center gap-3 text-xs text-gray-400">
                  <span>{t.source_device_sn}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded-full ${
                      t.valid ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-400'
                    }`}
                  >
                    {t.valid ? 'Valid' : 'Invalid'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  )
}

export default function Employees() {
  const [employees, setEmployees] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState(null)

  const load = useCallback(async () => {
    try {
      const list = await api.employees.list()
      setEmployees(list)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const filtered = employees.filter(
    (e) =>
      e.name.toLowerCase().includes(search.toLowerCase()) ||
      e.user_id.includes(search)
  )

  return (
    <div className="bg-white rounded-xl border border-gray-200 overflow-hidden flex" style={{ height: 'calc(100vh - 13rem)' }}>
      {/* Sidebar */}
      <div className="w-72 flex-shrink-0 border-r border-gray-200 flex flex-col">
        <div className="p-3 border-b border-gray-100">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search employees…"
            className="input w-full text-sm"
          />
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <p className="text-sm text-gray-400 text-center py-8">Loading…</p>
          ) : filtered.length === 0 ? (
            <p className="text-sm text-gray-400 text-center py-8">No results.</p>
          ) : (
            filtered.map((emp) => (
              <button
                key={emp.user_id}
                onClick={() => setSelected(emp)}
                className={`w-full text-left px-4 py-3 border-b border-gray-100 last:border-0 hover:bg-gray-50 transition-colors ${
                  selected?.user_id === emp.user_id ? 'bg-blue-50 border-l-2 border-l-blue-500' : ''
                }`}
              >
                <p className="text-sm font-medium text-gray-900 truncate">{emp.name}</p>
                <p className="text-xs text-gray-400 font-mono mt-0.5">{emp.user_id}</p>
              </button>
            ))
          )}
        </div>

        <div className="px-4 py-2 border-t border-gray-100 text-xs text-gray-400">
          {employees.length} employee{employees.length !== 1 ? 's' : ''}
        </div>
      </div>

      {/* Detail panel */}
      <DetailPanel employee={selected} />
    </div>
  )
}
