const BASE = '/api'

async function request(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  }
  if (body !== undefined) {
    opts.body = JSON.stringify(body)
  }
  const res = await fetch(BASE + path, opts)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`HTTP ${res.status}: ${text}`)
  }
  return res.json()
}

export const api = {
  getConfig: () => request('GET', '/config'),

  // Auth
  getMe:         () => request('GET', '/auth/me'),
  listAdmins:    () => request('GET', '/admins'),
  addAdmin:      (discord_id, discord_name) =>
                   request('POST', '/admins', { discord_id, discord_name }),
  removeAdmin:   (discord_id) => request('DELETE', `/admins/${discord_id}`),

  getReports: (status = 'all') =>
    request('GET', `/reports?status=${encodeURIComponent(status)}`),

  getReport: (id) => request('GET', `/reports/${id}`),

  updateReportStatus: (id, status) =>
    request('PUT', `/reports/${id}/status`, { status }),

  linkAction: (id, action) =>
    request('POST', `/links/${id}/action`, { action }),

  getWhois: (id) => request('GET', `/links/${id}/intel/whois`),
  getHost: (id) => request('GET', `/links/${id}/intel/host`),
  getReputation: (id) => request('GET', `/links/${id}/intel/reputation`),

  addNote: (reportId, note) =>
    request('POST', `/reports/${reportId}/notes`, { note }),

  setReporterMessage: (reportId, message) =>
    request('PUT', `/reports/${reportId}/reporter-message`, { message }),

  getPrivacyPolicy: () => request('GET', '/privacy'),
  setPrivacyPolicy: (content) => request('PUT', '/privacy', { content }),

  getToS: () => request('GET', '/tos'),
  setToS: (content) => request('PUT', '/tos', { content }),
}
