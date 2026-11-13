/** What each failure means to the person looking at the screen, and the one thing to do next. */
const RULES = {
  network: { title: 'Firewall not reachable', why: 'The browser could not open a connection to the Heimdall middleware.', action: 'retry' },
  timeout: { title: 'The firewall took too long', why: 'Free-tier hosts sleep when idle, and the first request after a nap can take up to a minute.', action: 'retry' },
  rate_limited: { title: 'Slow down for a moment', why: 'This address reached the per-minute limit for this kind of request.', action: 'wait' },
  session_locked: { title: 'This session is locked', why: 'Three requests were blocked inside ten minutes, so the session is paused.', action: 'newSession' },
  session_invalid: { title: 'Session expired', why: 'The server no longer recognises this session, usually after a restart.', action: 'newSession' },
  stream_token_invalid: { title: 'Live trace disconnected', why: 'The stream token ran out. Results still arrive, but layers will not animate.', action: 'reconnect' },
  empty_message: { title: 'Nothing to scan', why: 'Type a prompt first.', action: null },
  invalid_request: { title: 'The request was rejected', why: 'A field is missing or over its limit.', action: null },
  payload_too_large: { title: 'That is too long', why: 'The request body is over the server limit.', action: null },
  providers_unavailable: { title: 'No model answered', why: 'Gateway 1 finished, but every provider failed. The table below shows why.', action: 'retry' },
  invalid_admin_key: { title: 'Admin key rejected', why: 'This page needs the ADMIN_KEY set on the middleware.', action: 'adminKey' },
  admin_locked_out: { title: 'Too many wrong keys', why: 'This address is locked out of admin routes for a few minutes.', action: 'wait' },
  research_field_forbidden: { title: 'Research field refused', why: 'Layer switches and custom prompts need RESEARCH_MODE and the admin key.', action: null },
  internal_error: { title: 'Heimdall stopped this request', why: 'An internal error occurred. Nothing was sent to a model.', action: 'retry' },
  review_item_missing: { title: 'Already decided', why: 'Another reviewer decided this item, or it timed out.', action: 'retry' },
}

export function explain(error) {
  if (!error) return null
  if (error.status === 404 && error.message === 'Debug console disabled') {
    return { title: 'Debug console is off', why: 'It exposes rule internals, so it is disabled unless ENABLE_DEBUG_CONSOLE=true is set on the middleware.', action: null }
  }
  if (error.status === 403 && !RULES[error.code]) return RULES.invalid_admin_key
  const rule = RULES[error.code]
  if (rule) return { ...rule, why: error.code === 'invalid_request' || error.code === 'rate_limited' ? error.message : rule.why }
  return { title: 'The request failed', why: error.message || 'The server returned an error.', action: 'retry' }
}

export const PROVIDER_ERRORS = {
  no_api_key: ['No API key', 'Set this provider key on the multi-LLM backend.'],
  auth_failed: ['Key rejected', 'The provider refused the key. Rotate it or check its scope.'],
  rate_limited: ['Quota reached', 'The provider limited this key. Wait, or use a paid tier.'],
  timeout: ['Timed out', 'The provider did not answer in time.'],
  model_unavailable: ['Model retired', 'Update the model ID in the backend .env.'],
  circuit_open: ['Paused by breaker', 'Recent failures tripped the circuit breaker. It retries by itself.'],
  backend_unreachable: ['Backend down', 'The multi-LLM service is not responding on its port.'],
  upstream_error: ['Provider error', 'The provider returned an unexpected error.'],
}
