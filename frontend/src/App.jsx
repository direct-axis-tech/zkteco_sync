import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth'
import Login from './pages/Login'
import ChangePassword from './pages/ChangePassword'
import Devices from './pages/Devices'
import Employees from './pages/Employees'
import Attendance from './pages/Attendance'
import Settings from './pages/Settings'
import Layout from './components/Layout'

function Loading() {
  return (
    <div className="min-h-screen flex items-center justify-center text-sm text-gray-500">
      Loading…
    </div>
  )
}

// Requires a live session and a password that is not overdue for a change.
function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  if (!user) return <Navigate to="/login" replace />
  if (user.must_change_password) return <Navigate to="/change-password" replace />
  return children
}

// Requires a live session only — the one route a user under a forced password
// change is allowed to reach.
function SessionRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <Loading />
  if (!user) return <Navigate to="/login" replace />
  return children
}

function Routing() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/change-password"
        element={<SessionRoute><ChangePassword /></SessionRoute>}
      />
      <Route
        path="/"
        element={<ProtectedRoute><Layout /></ProtectedRoute>}
      >
        <Route index element={<Navigate to="/devices" replace />} />
        <Route path="devices" element={<Devices />} />
        <Route path="employees" element={<Employees />} />
        <Route path="attendance" element={<Attendance />} />
        <Route path="settings" element={<Settings />} />
      </Route>
      <Route path="*" element={<Navigate to="/devices" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routing />
      </AuthProvider>
    </BrowserRouter>
  )
}
