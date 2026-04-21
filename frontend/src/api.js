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
  hrmSync: {
    status: () => request('GET', '/hrm-sync/status'),
    run: () => request('POST', '/hrm-sync/run'),
  },
  attendance: {
    list: (params = {}) => {
      const q = new URLSearchParams()
      if (params.device_sn) q.set('device_sn', params.device_sn)
      if (params.user_id) q.set('user_id', params.user_id)
      if (params.from_date) q.set('from_date', params.from_date)
      if (params.to_date) q.set('to_date', params.to_date)
      if (params.limit != null) q.set('limit', params.limit)
      if (params.offset != null) q.set('offset', params.offset)
      return request('GET', `/attendance?${q}`)
    },
  },
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
    pushUser: (sn, userId) => request('POST', `/devices/${sn}/users/${userId}/push`),
    removeUser: (sn, userId) => request('DELETE', `/devices/${sn}/users/${userId}`),
    pushTemplates: (sn, userId) => request('POST', `/devices/${sn}/users/${userId}/templates/push`),
    enrollUser: (sn, userId, fingerId) =>
      request('POST', `/devices/${sn}/users/${userId}/enroll`, { finger_id: fingerId }),
    deleteTemplate: (sn, userId, fingerId) =>
      request('DELETE', `/devices/${sn}/users/${userId}/templates/${fingerId}`),
  },
}
