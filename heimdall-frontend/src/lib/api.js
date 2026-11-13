/**
 * Every network call goes through here, so every failure arrives at the UI in one
 * shape: an ApiError with a stable code, a plain message and, when known, what to do.
 */
export const BASE_URL = (import.meta.env.VITE_HEIMDALL_URL || '/api').replace(/\/$/, '')

export class ApiError extends Error {
  constructor({ status = 0, code = 'unknown', message = 'Something went wrong.', hint = '', retryAfter = null, providers = null, incident = null }) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.hint = hint
    this.retryAfter = retryAfter
    this.providers = providers
    this.incident = incident
  }
}

const adminStore = 'heimdall_admin_key'

export function getAdminKey() {
  try { return sessionStorage.getItem(adminStore) || '' } catch { return '' }
}

export function setAdminKey(value) {
  try {
    if (value) sessionStorage.setItem(adminStore, value)
    else sessionStorage.removeItem(adminStore)
  } catch { /* storage unavailable: the key lasts for this view only */ }
}

export async function api(path, { method = 'GET', body, headers = {}, admin = false, signal, timeout = 90000 } = {}) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort('timeout'), timeout)
  signal?.addEventListener('abort', () => controller.abort(signal.reason), { once: true })
  const finalHeaders = { ...headers }
  if (body !== undefined) finalHeaders['Content-Type'] = 'application/json'
  if (admin) finalHeaders['x-admin-key'] = getAdminKey()

  let response
  try {
    response = await fetch(`${BASE_URL}${path}`, {
      method,
      headers: finalHeaders,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    })
  } catch (error) {
    if (signal?.aborted) throw error
    if (controller.signal.aborted) {
      throw new ApiError({ code: 'timeout', message: 'The firewall took too long to answer.', hint: 'A sleeping host can need up to a minute to wake. Try again.' })
    }
    throw new ApiError({ code: 'network', message: 'The firewall could not be reached.', hint: 'Check that the middleware is running on port 8000.' })
  } finally {
    clearTimeout(timer)
  }

  if (response.status === 204) return null
  const text = await response.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch { /* an HTML error page from a proxy */ }

  if (!response.ok) {
    // A proxy or a sleeping host answers with no JSON body; the firewall never does.
    if (!data && response.status >= 500) {
      throw new ApiError({ status: response.status, code: 'network', message: 'The firewall could not be reached.', hint: 'Check that the middleware is running on port 8000. A sleeping host can need a minute to wake.' })
    }
    const detail = data?.detail
    if (detail && typeof detail === 'object') {
      throw new ApiError({
        status: response.status, code: detail.code || `http_${response.status}`, message: detail.message || 'The request failed.',
        hint: detail.hint || '', retryAfter: detail.retry_after ?? null, providers: detail.providers || null, incident: detail.incident || null,
      })
    }
    throw new ApiError({
      status: response.status, code: `http_${response.status}`,
      message: typeof detail === 'string' ? detail : `The server answered ${response.status}.`,
      retryAfter: Number(response.headers.get('Retry-After')) || null,
    })
  }
  return data
}

const SESSION_STORE = 'heimdall_session'

export function storedSession() {
  try { return JSON.parse(sessionStorage.getItem(SESSION_STORE) || 'null') } catch { return null }
}

export function clearSession() {
  try { sessionStorage.removeItem(SESSION_STORE) } catch { /* nothing stored */ }
}

/** Ask for a session (or a new stream token for the one this tab owns). */
export async function initSession({ fresh = false } = {}) {
  const existing = fresh ? null : storedSession()
  const data = await api('/session/init', {
    method: 'POST',
    body: {},
    headers: existing?.session_token ? { 'X-Heimdall-Session': existing.session_token } : {},
  })
  try {
    sessionStorage.setItem(SESSION_STORE, JSON.stringify({ session_id: data.session_id, session_token: data.session_token }))
  } catch { /* storage unavailable: session lasts for this view only */ }
  return data
}
