import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, BASE_URL, api, clearSession, initSession, storedSession } from '../lib/api.js'
import { LAYERS } from '../lib/layers.js'
import { useStats } from '../context/StatsContext.jsx'

const blankLayers = () => Object.fromEntries(LAYERS.map((l) => [l.id, { status: 'idle', latency: null, detail: null }]))

/**
 * One tab, one server-issued session, one live stream. REST is the source of truth for
 * the result, so a dropped stream degrades the animation, never the answer.
 */
export function useFirewall() {
  const [layers, setLayers] = useState(blankLayers)
  const [verdicts, setVerdicts] = useState({})
  const [providers, setProviders] = useState({})
  const [events, setEvents] = useState([])
  const [connection, setConnection] = useState('connecting')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [result, setResult] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [held, setHeld] = useState(false)
  const stream = useRef(null)
  const retry = useRef({ timer: null, count: 0 })
  const alive = useRef(true)
  const { record } = useStats()

  const log = useCallback((kind, text, tone = 'muted') => {
    const now = new Date()
    setEvents((prev) => [...prev.slice(-120), { id: `${now.getTime()}-${Math.random()}`, at: now.toLocaleTimeString([], { hour12: false }), kind, text, tone }])
  }, [])

  const handle = useCallback((data) => {
    switch (data.event) {
      case 'layer':
        setLayers((prev) => ({ ...prev, [data.layer]: {
          status: String(data.status || '').toLowerCase(), latency: data.latency_ms ?? null,
          detail: data.reason || data.detail || null, confidence: data.confidence ?? null, flags: data.flags ?? null,
        } }))
        log(data.layer, `${data.name}: ${String(data.status).toLowerCase()}`, data.status === 'BLOCK' ? 'bad' : data.status === 'FLAG' ? 'accent' : 'muted')
        break
      case 'verdict':
        setVerdicts((prev) => ({ ...prev, [data.gateway]: data }))
        log(data.gateway, `Verdict ${data.verdict}${data.fail_closed ? ' (arbiter unreachable)' : ''}`, data.verdict === 'BLOCK' ? 'bad' : 'ok')
        break
      case 'llm_start':
        log('LLM', `Querying ${data.providers.join(', ')}`)
        break
      case 'llm_result':
        setProviders((prev) => ({ ...prev, [data.provider]: { ...prev[data.provider], ...data } }))
        log('LLM', `${data.provider}: ${data.ok ? 'answered' : data.error_code || 'failed'}`, data.ok ? 'muted' : 'accent')
        break
      case 'documents':
        log('DOC', `${data.reports.filter((r) => r.quarantined).length} of ${data.reports.length} documents quarantined`)
        break
      case 'held_for_review':
        setHeld(true)
        log('HITL', 'Held for human review', 'accent')
        break
      case 'complete':
        if (data.llm_responses) setProviders((prev) => ({ ...prev, ...data.llm_responses }))
        // A reviewer decision arrives here long after the original request ended.
        setResult((prev) => (prev?.status === 'pending' ? { ...prev, reply: data.reply, blocked: data.blocked, status: 'resolved', verdict_g1: data.blocked ? 'BLOCK' : 'PASS' } : prev))
        setHeld(false)
        break
      case 'error':
        log('SYS', data.detail || 'Server error', 'bad')
        break
      default:
        break
    }
  }, [log])

  const connect = useCallback(async ({ fresh = false } = {}) => {
    clearTimeout(retry.current.timer)
    stream.current?.close()
    setConnection('connecting')
    try {
      const session = await initSession({ fresh })
      if (!alive.current) return
      const source = new EventSource(`${BASE_URL}/stream/${session.stream_token}`)
      stream.current = source
      source.onopen = () => { retry.current.count = 0; setConnection('connected') }
      source.onmessage = (message) => {
        try {
          const data = JSON.parse(message.data)
          if (data.event === 'timeout') { source.close(); connect(); return }
          if (data.event !== 'ping') handle(data)
        } catch { /* a malformed frame must not break the stream */ }
      }
      source.onerror = () => {
        source.close()
        schedule()
      }
    } catch {
      schedule()
    }

    function schedule() {
      if (!alive.current) return
      setConnection('disconnected')
      retry.current.count += 1
      if (retry.current.count > 8) { setConnection('stopped'); return }
      retry.current.timer = setTimeout(connect, Math.min(16000, 1000 * 2 ** (retry.current.count - 1)))
    }
  }, [handle])

  useEffect(() => {
    alive.current = true
    connect()
    return () => {
      alive.current = false
      clearTimeout(retry.current.timer)
      stream.current?.close()
    }
  }, [connect])

  const reset = useCallback(() => {
    setLayers(blankLayers()); setVerdicts({}); setProviders({}); setEvents([]); setError(null); setResult(null); setAnalysis(null); setHeld(false)
  }, [])

  const send = useCallback(async (message, documents = []) => {
    reset()
    setBusy(true)
    const session = storedSession()
    // /scan is deterministic and free: it supplies the evidence panel while the model runs.
    api('/scan', { method: 'POST', body: { text: message, documents } }).then(setAnalysis).catch(() => setAnalysis(null))
    try {
      const data = await api('/chat', {
        method: 'POST',
        body: { message, documents },
        headers: {
          ...(session?.session_token ? { 'X-Heimdall-Session': session.session_token } : {}),
          'X-Heimdall-Policy': localStorage.getItem('heimdall_active_policy') || 'default',
        },
      })
      setResult(data)
      if (data.llm_responses?.groq) setProviders(data.llm_responses)
      record({
        verdict: data.blocked ? 'BLOCK' : data.status === 'pending' ? 'REVIEW' : data.sanitized ? 'SANITIZE' : 'PASS',
        latencyMs: data.latency_total_ms, attackType: data.attack_type,
      })
      return data
    } catch (err) {
      const failure = err instanceof ApiError ? err : new ApiError({ message: String(err) })
      setError(failure)
      if (failure.providers) setProviders(Object.fromEntries(Object.entries(failure.providers).map(([k, v]) => [k, { ok: false, error_code: v }])))
      throw failure
    } finally {
      setBusy(false)
    }
  }, [record, reset])

  const newSession = useCallback(() => { clearSession(); reset(); connect({ fresh: true }) }, [connect, reset])

  return { layers, verdicts, providers, events, connection, busy, error, result, analysis, held, send, reset, reconnect: connect, newSession, setError }
}
