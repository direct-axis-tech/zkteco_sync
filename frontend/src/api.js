// In dev Vite proxies /api → localhost:8000 (strips /api prefix)
// In production the frontend is served by FastAPI on the same origin
const BASE = import.meta.env.PROD ? '' : '/api'

function token() {
  return localStorage.getItem('token')
}

async function request(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token() ? { Authorization: `Bearer ${token()}` } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  })

  if (res.status === 401) {
    localStorage.removeItem('token')
    window.location.href = '/login'
    throw new Error('Unauthorized')
  }

  if (res.status === 204) return null

  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || 'Request failed')
  return data
}

export const api = {
  employees: {
    list: () => request('GET', '/employees'),
    get: (userId) => request('GET', `/employees/${userId}`),
    getDevices: (userId) => request('GET', `/employees/${userId}/devices`),
    getTemplates: (userId) => request('GET', `/employees/${userId}/templates`),
  },
  auth: {
    login: (username, password) =>
      request('POST', '/auth/login', { username, password }),
    verify: (password) =>
      request('POST', '/auth/verify', { password }),
  },
  devices: {
    list: () => request('GET', '/devices'),
    create: (data) => request('POST', '/devices', data),
    update: (sn, data) => request('PATCH', `/devices/${sn}`, data),
    delete: (sn) => request('DELETE', `/devices/${sn}`),
    pull: (sn) => request('POST', `/devices/${sn}/pull`),
    pullEmployees: (sn) => request('POST', `/devices/${sn}/pull/employees`),
    pullAttendance: (sn) => request('POST', `/devices/${sn}/pull/attendance`),
    pullTemplates: (sn) => request('POST', `/devices/${sn}/templates/pull`),
    info: (sn) => request('GET', `/devices/${sn}/info`),
    getTime: (sn) => request('GET', `/devices/${sn}/time`),
    setTime: (sn, data) => request('POST', `/devices/${sn}/time`, data),
    unlock: (sn, seconds = 3) => request('POST', `/devices/${sn}/unlock`, { seconds }),
    writeLcd: (sn, line, text) => request('POST', `/devices/${sn}/lcd`, { line, text }),
    clearLcd: (sn) => request('DELETE', `/devices/${sn}/lcd`),
    clearAttendance: (sn) => request('DELETE', `/devices/${sn}/attendance`),
    restart: (sn) => request('POST', `/devices/${sn}/restart`),
    queueCommand: (sn, command) => request('POST', `/devices/${sn}/commands`, { command }),
    listUsers: (sn) => request('GET', `/devices/${sn}/users`),
    pushBulk: (sn, user_ids) => request('POST', `/devices/${sn}/users/push_bulk`, { user_ids }),
  },
}
