import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import { useAuth } from '../auth'
import KebabMenu from '../components/KebabMenu'

const ROLES = ['admin', 'viewer']

function RoleBadge({ role }) {
  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
        role === 'admin' ? 'bg-purple-100 text-purple-700' : 'bg-gray-100 text-gray-600'
      }`}
    >
      {role}
    </span>
  )
}

function StatusBadge({ active }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium ${
        active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'
      }`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-green-500' : 'bg-gray-400'}`} />
      {active ? 'Active' : 'Inactive'}
    </span>
  )
}

function Toast({ message, type, onDismiss }) {
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

function Field({ label, required, hint, children }) {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 mb-1">
        {label}
        {required && <span className="text-red-500 ml-0.5">*</span>}
      </label>
      {children}
      {hint && <p className="text-xs text-gray-400 mt-1">{hint}</p>}
    </div>
  )
}

function UserFormModal({ mode, user, isSelf, onSave, onClose }) {
  const isEdit = mode === 'edit'
  const [form, setForm] = useState({ username: '', full_name: '', password: '', role: 'viewer' })
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (isEdit && user) {
      setForm({ username: user.username, full_name: user.full_name || '', password: '', role: user.role })
    }
  }, [isEdit, user])

  function set(field, value) {
    setForm((f) => ({ ...f, [field]: value }))
  }

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setSaving(true)
    try {
      const payload = isEdit
        ? { full_name: form.full_name || null, role: form.role }
        : { username: form.username, full_name: form.full_name || null, password: form.password, role: form.role }
      await onSave(payload)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40" />
      <div className="relative bg-white rounded-2xl shadow-xl w-full max-w-md mx-4 p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold text-gray-900">{isEdit ? 'Edit User' : 'Add User'}</h2>
          <button type="button" onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label="Username" required>
            <input
              type="text"
              required
              disabled={isEdit}
              value={form.username}
              onChange={(e) => set('username', e.target.value)}
              className="input disabled:bg-gray-100 disabled:text-gray-400"
            />
          </Field>

          <Field label="Full Name">
            <input
              type="text"
              value={form.full_name}
              onChange={(e) => set('full_name', e.target.value)}
              className="input"
            />
          </Field>

          {!isEdit && (
            <Field label="Setup Password" required hint="The operator must change this on first sign-in.">
              <input
                type="password"
                required
                minLength={8}
                value={form.password}
                onChange={(e) => set('password', e.target.value)}
                className="input"
              />
            </Field>
          )}

          <Field label="Role" required hint={isSelf ? 'You cannot change your own role.' : undefined}>
            <select
              disabled={isSelf}
              value={form.role}
              onChange={(e) => set('role', e.target.value)}
              className="input disabled:bg-gray-100 disabled:text-gray-400"
            >
              {ROLES.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </Field>

          {error && (
            <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>
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
              {saving ? 'Saving…' : isEdit ? 'Save Changes' : 'Add User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function ResetPasswordModal({ user, onSave, onClose }) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setSaving(true)
    try {
      await onSave(password)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40" />
      <div className="relative bg-white rounded-2xl shadow-xl w-full max-w-sm mx-4 p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold text-gray-900">Reset Password</h2>
          <button type="button" onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
            ✕
          </button>
        </div>

        <p className="text-sm text-gray-500 mb-4">
          Sets a new setup password for <span className="font-medium text-gray-700">{user.username}</span>. They
          will be forced to change it on their next sign-in, and any session of theirs that is live right now ends
          immediately.
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <Field label="New Password" required>
            <input
              type="password"
              required
              minLength={8}
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="input"
            />
          </Field>

          {error && (
            <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>
          )}

          <div className="flex gap-3">
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
              {saving ? 'Saving…' : 'Reset Password'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Users() {
  const { user: me } = useAuth()
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [modal, setModal] = useState(null) // { mode: 'create' | 'edit', user? }
  const [resetTarget, setResetTarget] = useState(null)
  const [toast, setToast] = useState(null)

  const showToast = useCallback((message, type = 'success') => setToast({ message, type }), [])
  const dismissToast = useCallback(() => setToast(null), [])

  const loadUsers = useCallback(async () => {
    try {
      setUsers(await api.users.list())
    } catch (err) {
      showToast(err.message || 'Failed to load users', 'error')
    } finally {
      setLoading(false)
    }
  }, [showToast])

  useEffect(() => {
    loadUsers()
  }, [loadUsers])

  async function handleSave(formData) {
    if (modal.mode === 'create') {
      await api.users.create(formData)
      showToast('User created')
    } else {
      await api.users.update(modal.user.id, formData)
      showToast('User updated')
    }
    setModal(null)
    loadUsers()
  }

  async function handleResetPassword(newPassword) {
    await api.users.resetPassword(resetTarget.id, newPassword)
    showToast(`Password reset for ${resetTarget.username}`)
    setResetTarget(null)
    loadUsers()
  }

  async function handleToggleActive(u) {
    try {
      await api.users.update(u.id, { is_active: !u.is_active })
      showToast(u.is_active ? `${u.username} deactivated` : `${u.username} activated`)
      loadUsers()
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  async function handleDelete(u) {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return
    try {
      await api.users.delete(u.id)
      showToast('User deleted')
      loadUsers()
    } catch (err) {
      showToast(err.message, 'error')
    }
  }

  function menuItems(u) {
    // SessionOut (GET /auth/me) carries no numeric id, only username — that's
    // the only stable field we can compare a row against to know it's "you".
    const isSelf = u.username === me?.username
    return [
      { label: 'Edit', onClick: () => setModal({ mode: 'edit', user: u }) },
      { label: 'Reset Password', onClick: () => setResetTarget(u) },
      {
        label: u.is_active ? 'Deactivate' : 'Activate',
        danger: u.is_active,
        disabled: isSelf && u.is_active,
        onClick: () => handleToggleActive(u),
      },
      'divider',
      { label: 'Delete', danger: true, disabled: isSelf, onClick: () => handleDelete(u) },
    ]
  }

  function formatDate(iso) {
    if (!iso) return '—'
    return new Date(iso).toLocaleString()
  }

  return (
    <>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-gray-900">Users</h1>
        <button
          onClick={() => setModal({ mode: 'create' })}
          className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors"
        >
          + Add User
        </button>
      </div>

      <div className="bg-white rounded-xl border border-gray-200">
        {loading ? (
          <div className="p-12 text-center text-sm text-gray-400">Loading…</div>
        ) : users.length === 0 ? (
          <div className="p-12 text-center text-sm text-gray-400">No operators yet.</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-50 [&>th:first-child]:rounded-tl-xl [&>th:last-child]:rounded-tr-xl">
                <th className="text-left px-4 py-3 font-medium text-gray-500">Username</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Name</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Role</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Status</th>
                <th className="text-left px-4 py-3 font-medium text-gray-500">Last Login</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr
                  key={u.id}
                  className="border-b border-gray-100 last:border-0 hover:bg-gray-50 transition-colors"
                >
                  <td className="px-4 py-3 font-medium text-gray-900">
                    {u.username}
                    {u.username === me?.username && <span className="text-gray-400 font-normal"> (you)</span>}
                  </td>
                  <td className="px-4 py-3 text-gray-500">
                    {u.full_name || <span className="text-gray-400">—</span>}
                  </td>
                  <td className="px-4 py-3"><RoleBadge role={u.role} /></td>
                  <td className="px-4 py-3"><StatusBadge active={u.is_active} /></td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{formatDate(u.last_login_at)}</td>
                  <td className="px-4 py-3 text-right">
                    <KebabMenu items={menuItems(u)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {modal && (
        <UserFormModal
          mode={modal.mode}
          user={modal.user}
          isSelf={modal.user?.username === me?.username}
          onSave={handleSave}
          onClose={() => setModal(null)}
        />
      )}

      {resetTarget && (
        <ResetPasswordModal
          user={resetTarget}
          onSave={handleResetPassword}
          onClose={() => setResetTarget(null)}
        />
      )}

      {toast && <Toast message={toast.message} type={toast.type} onDismiss={dismissToast} />}
    </>
  )
}
