import { Outlet, NavLink, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'

const tabs = [
  { label: 'Devices', to: '/devices' },
  { label: 'Employees', to: '/employees' },
  { label: 'Attendance', to: '/attendance' },
  { label: 'Settings', to: '/settings' },
]

export default function Layout() {
  const navigate = useNavigate()
  const { user, refresh } = useAuth()

  async function logout() {
    // Revoke server-side first; the cookie alone means nothing afterwards.
    try {
      await api.auth.logout()
    } finally {
      await refresh()
      navigate('/login', { replace: true })
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-6xl mx-auto px-6">
          {/* Top bar */}
          <div className="flex items-center justify-between h-14">
            <span className="font-semibold text-gray-900">ZKTeco Sync</span>
            <div className="flex items-center gap-4">
              <span className="text-sm text-gray-500">{user?.username}</span>
              <button
                onClick={logout}
                className="text-sm text-gray-500 hover:text-gray-800 transition-colors"
              >
                Logout
              </button>
            </div>
          </div>

          {/* Tabs */}
          <nav className="flex gap-1">
            {tabs.map((tab) => (
              <NavLink
                key={tab.to}
                to={tab.to}
                className={({ isActive }) =>
                  `px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                    isActive
                      ? 'border-blue-600 text-blue-600'
                      : 'border-transparent text-gray-500 hover:text-gray-800'
                  }`
                }
              >
                {tab.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8">
        <Outlet />
      </main>
    </div>
  )
}
