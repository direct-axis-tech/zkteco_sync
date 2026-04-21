import { Outlet, NavLink, useNavigate } from 'react-router-dom'

const tabs = [
  { label: 'Devices', to: '/devices' },
  { label: 'Employees', to: '/employees' },
  { label: 'Attendance', to: '/attendance' },
  { label: 'Settings', to: '/settings' },
]

export default function Layout() {
  const navigate = useNavigate()

  function logout() {
    localStorage.removeItem('token')
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-6xl mx-auto px-6">
          {/* Top bar */}
          <div className="flex items-center justify-between h-14">
            <span className="font-semibold text-gray-900">ZKTeco Sync</span>
            <button
              onClick={logout}
              className="text-sm text-gray-500 hover:text-gray-800 transition-colors"
            >
              Logout
            </button>
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
