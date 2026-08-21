// In dev Vite proxies /api → localhost:8000 (strips /api prefix)
// In production the frontend is served by FastAPI on the same origin
const BASE = import.meta.env.PROD ? '' : '/api'

// Auth rides on an HttpOnly session cookie the browser sets at login, so
// no token is ever written to browser storage. The matching CSRF token lives in
// this module variable only — memory the page can read but another origin
// cannot — and is re-seeded from GET /auth/me after a reload.
const UNSAFE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

let csrfToken = null

export function setCsrfToken(value) {
  csrfToken = value || null
}

async function request(method, path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      // On every call, not just the unsafe ones: several client-side routes
      // (/devices, /employees, /attendance, /users) are also real API paths,
      // and the server tells the two apart by this flag — without it, a plain
      // GET /devices is read as a browser navigating to the page and answered
      // with the app shell instead of JSON. See SpaNavigationMiddleware.
      'X-Requested-With': 'XMLHttpRequest',
      ...(UNSAFE_METHODS.has(method) && csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  })

  // /auth/* callers render their own errors — a redirect there would wipe the
  // "wrong password" message off the login form.
  if (res.status === 401 && !path.startsWith('/auth/')) {
    csrfToken = null
    // Bounce through the app root and let the router send an
    // unauthenticated visitor on to /login from there.
    window.location.href = '/'
    throw new Error('Unauthorized')
  }

  if (res.status === 204) return null

  const data = await res.json()
  if (!res.ok) throw new Error(data.detail || 'Request failed')
  return data
}

export const api = {
  hrmSync: {
    status: () => request('GET', '/hrm-sync'),
    update: (data) => request('PUT', '/hrm-sync', data),
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
    // Admin-only. Creating a person here does NOT put them on any device —
    // that is a separate, explicit per-device push.
    create: (data) => request('POST', '/employees', data),
    // Only the fields passed are touched; an empty string clears one. That is
    // the difference between an operator edit and a device upload, which may
    // never empty a field out.
    update: (userId, data) => request('PATCH', `/employees/${userId}`, data),
    get: (userId) => request('GET', `/employees/${userId}`),
    getDevices: (userId) => request('GET', `/employees/${userId}/devices`),
    getTemplates: (userId) => request('GET', `/employees/${userId}/templates`),
    // Biometrics captured at a terminal (faces, fingers) — described, never
    // handed over: the template bytes themselves stay on the server. What
    // matters here is `source_device_sn`, the one terminal each will never be
    // pushed back to.
    getBiometrics: (userId) => request('GET', `/employees/${userId}/biometrics`),
    // Admin-only. Refused with 409 while any device still holds this pin —
    // read the 409's `message` to the operator; it names the doors. On
    // success, cascades device_employees/biometric_templates/employee_photos/
    // fingerprint_templates and leaves attendance_logs untouched.
    delete: (userId) => request('DELETE', `/employees/${userId}`),
    // A URL, not a fetch: this is meant for an <img src>, so the browser
    // requests and caches it the ordinary way. Deliberately never inlined
    // into the employee list response — that would be ~100KB per person.
    photoUrl: (userId) => `${BASE}/employees/${encodeURIComponent(userId)}/photo`,
  },
  auth: {
    login: async (username, password) => {
      const data = await request('POST', '/auth/login', { username, password })
      setCsrfToken(data.csrf_token)
      return data
    },
    logout: async () => {
      await request('POST', '/auth/logout')
      setCsrfToken(null)
    },
    me: async () => {
      const data = await request('GET', '/auth/me')
      setCsrfToken(data.csrf_token)
      return data
    },
    changePassword: (current_password, new_password) =>
      request('POST', '/auth/change-password', { current_password, new_password }),
    verify: (password) =>
      request('POST', '/auth/verify', { password }),
  },
  devices: {
    list: (status) => request('GET', status ? `/devices?status=${status}` : '/devices'),
    create: (data) => request('POST', '/devices', data),
    approve: (sn) => request('POST', `/devices/${sn}/approve`),
    reject: (sn) => request('POST', `/devices/${sn}/reject`),
    // Time-boxed window during which an unrecognised serial is filed for
    // approval instead of being refused outright.
    getPairing: () => request('GET', '/devices/pairing'),
    openPairing: (minutes) => request('POST', '/devices/pairing', { minutes }),
    closePairing: () => request('DELETE', '/devices/pairing'),
    update: (sn, data) => request('PATCH', `/devices/${sn}`, data),
    // Its own endpoint, not part of update(): changing a device's timezone
    // relabels every attendance record it ever pushed.
    setTimezone: (sn, timezone) => request('PATCH', `/devices/${sn}/timezone`, { timezone }),
    // Its own endpoint too: correcting the PUSH protocol family pins it
    // against the automatic DeviceType/ATTLOG classification in adms.py.
    setProtocol: (sn, protocol) => request('PATCH', `/devices/${sn}/protocol`, { protocol }),
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
    // The outbox: what this device still owes us. A row here is queued, not
    // delivered — the device collects it on its next poll.
    listCommands: (sn) => request('GET', `/devices/${sn}/commands`),
    // One entry per revocation this device still owes somebody — the two
    // `DATA DELETE` commands E8 sends already merged server-side (E13), so
    // this is the one place both surfaces (Employees.jsx, CommandsDrawer.jsx)
    // read the split-state judgement from, rather than each re-deriving it.
    listRevocations: (sn, userId) =>
      request('GET', `/devices/${sn}/revocations${userId ? `?user_id=${encodeURIComponent(userId)}` : ''}`),
    // Concluded commands: what the device said about each one. A `failed`
    // row with a return_code is the device having refused it.
    commandHistory: (sn) => request('GET', `/devices/${sn}/commands/history`),
    // Withdraws an outstanding command. Cancelling `pending` genuinely stops
    // delivery; cancelling `sent` only removes our record — the device may
    // already have collected and acted on it. The response `message` says
    // which happened; render that, do not infer success from an empty list.
    cancelCommand: (sn, commandId) =>
      request('DELETE', `/devices/${sn}/commands/${commandId}`),
    // Requeues a failed command as a brand-new outbox row; the history row
    // being retried is left untouched. `was_device_refusal` is true when the
    // device rejected it last time — very likely to be refused again.
    retryCommand: (sn, logId) =>
      request('POST', `/devices/${sn}/commands/history/${logId}/retry`),
    listUsers: (sn) => request('GET', `/devices/${sn}/users`),
    pushBulk: (sn, user_ids) => request('POST', `/devices/${sn}/users/push_bulk`, { user_ids }),
    pushUser: (sn, userId) => request('POST', `/devices/${sn}/users/${userId}/push`),
    // Takes a person off a device. On an `acc` terminal this QUEUES the
    // removal and answers 202 `status: "queued"` — the door has not been told
    // yet and the person can still open it until it acknowledges. Callers
    // must read `status` and must not report a queued revocation as done.
    removeUser: (sn, userId) => request('DELETE', `/devices/${sn}/users/${userId}`),
    // Calls off a revocation the device has not collected yet. The escape
    // hatch for the 409 that a push gets while a delete is outstanding.
    cancelRevocation: (sn, userId) =>
      request('DELETE', `/devices/${sn}/users/${userId}/revocation`),
    pushTemplates: (sn, userId) => request('POST', `/devices/${sn}/users/${userId}/templates/push`),
    enrollUser: (sn, userId, fingerId) =>
      request('POST', `/devices/${sn}/users/${userId}/enroll`, { finger_id: fingerId }),
    deleteTemplate: (sn, userId, fingerId) =>
      request('DELETE', `/devices/${sn}/users/${userId}/templates/${fingerId}`),
  },
  users: {
    list: () => request('GET', '/users'),
    create: (data) => request('POST', '/users', data),
    update: (id, data) => request('PATCH', `/users/${id}`, data),
    resetPassword: (id, newPassword) =>
      request('POST', `/users/${id}/reset-password`, { new_password: newPassword }),
    delete: (id) => request('DELETE', `/users/${id}`),
  },
  audit: {
    list: (params = {}) => {
      const q = new URLSearchParams()
      if (params.actor) q.set('actor', params.actor)
      if (params.action) q.set('action', params.action)
      if (params.from_date) q.set('from_date', params.from_date)
      if (params.to_date) q.set('to_date', params.to_date)
      if (params.limit != null) q.set('limit', params.limit)
      if (params.offset != null) q.set('offset', params.offset)
      return request('GET', `/audit?${q}`)
    },
  },
}
