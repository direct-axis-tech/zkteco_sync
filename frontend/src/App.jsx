import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Login from './pages/Login'
import Devices from './pages/Devices'
import Employees from './pages/Employees'
import Attendance from './pages/Attendance'
import Settings from './pages/Settings'
import Layout from './components/Layout'

function ProtectedRoute({ children }) {
  return localStorage.getItem('token') ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
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
    </BrowserRouter>
  )
}
