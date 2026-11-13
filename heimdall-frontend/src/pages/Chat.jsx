import { useEffect, useRef, useState } from 'react'
import { Pipeline } from '../components/Pipeline.jsx'
import { Empty, ErrorPanel, Findings, PercentScale, Providers, SeverityScale, Verdict } from '../components/ui.jsx'
import { useFirewall } from '../hooks/useFirewall.js'
import { api } from '../lib/api.js'
import { fmtMs } from '../lib/layers.js'
import GradualBlur from '../components/reactbits/GradualBlur.jsx'
import Counter from '../components/reactbits/Counter.jsx'

const CONNECTION = {
  connected: ['Live trace on', 'ok'], connecting: ['Connecting', 'muted'],
  disconnected: ['Reconnecting', 'accent'], stopped: ['Live trace off', 'bad'],
}

function outcome(result) {
  if (!result) return null
  if (result.status === 'pending') return 'REVIEW'
  if (result.blocked) return 'BLOCK'
  return result.sanitized ? 'SANITIZE' : 'PASS'
}

function explainVerdict(result, analysis) {
  if (!result) return null
  if (result.status === 'pending') return 'The arbiter was unsure. A reviewer now decides, and the answer appears here.'
  if (result.blocked) {
    if (result.verdict_g2 === 'BLOCK') return `The model answered, but Gateway 2 withheld it: ${result.reason || 'a critical output rule fired'}.`
    return result.reason || 'Gateway 1 stopped this prompt before any model saw it.'
  }
  if (result.degraded) return 'The arbiter was unreachable. This prompt had only weak signals, so it was fenced off as data and forwarded.'
  if (result.sanitized) return 'The content was repaired before delivery.'
  return analysis?.flags?.length ? 'Weak signals only. The arbiter cleared them.' : 'No layer raised a finding.'
}

export default function Chat() {
  const fw = useFirewall()
  const [text, setText] = useState('')
  const [docOpen, setDocOpen] = useState(false)
  const [doc, setDoc] = useState('')
  const [messages, setMessages] = useState([])
  const logEnd = useRef(null)
  const lastSent = useRef(null)

  useEffect(() => { logEnd.current?.scrollIntoView({ block: 'nearest' }) }, [messages])

  useEffect(() => {
    const r = fw.result
    if (!r) return
    setMessages((m) => {
      const copy = m.filter((x) => x.id !== r.request_id)
      return [...copy, { id: r.request_id, role: 'firewall', text: r.reply, verdict: outcome(r) }]
    })
  }, [fw.result])

  async function submit(value = text, docText = doc) {
    const message = value.trim()
    if (!message || fw.busy) return
    lastSent.current = { value: message, docText }
    setMessages((m) => [...m, { id: `u-${Date.now()}`, role: 'you', text: message }])
    setText('')
    const documents = docOpen && docText.trim() ? [{ source: 'pasted document', text: docText.trim() }] : []
    try { await fw.send(message, documents) } catch { /* shown by ErrorPanel */ }
  }

  async function redTeam() {
    try {
      const data = await api('/generate-attack', { method: 'POST', body: {} })
      setText(data.attack_prompt)
    } catch (error) { fw.setError(error) }
  }

  const severity = fw.analysis?.max_severity || null
  const [connWord, connTone] = CONNECTION[fw.connection] || CONNECTION.connecting
  const reports = fw.result?.documents?.length ? fw.result.documents : fw.analysis?.documents || []

  return (
    <main className="console">
      <section className="console-chat" aria-label="Conversation">
        <div className="console-bar">
          <h1 className="h-title">Console</h1>
          <div className="row">
            <span className={`chip chip-${connTone}`}>{connWord}</span>
            {fw.connection === 'stopped' && <button className="btn btn-s" onClick={() => fw.reconnect()}>Reconnect</button>}
            <button className="btn btn-s" onClick={() => { setMessages([]); fw.newSession() }}>New session</button>
          </div>
        </div>

        <div className="log-wrap"><div className="log" aria-live="polite">
          {messages.length === 0 && (
            <Empty title="Send a prompt to watch it cross both gateways">
              Try a question, then a red-team sample, and compare the trace.
            </Empty>
          )}
          {messages.map((m) => (
            <article key={m.id} className={`msg msg-${m.role}`}>
              <header><span>{m.role === 'you' ? 'You' : 'Heimdall'}</span>{m.verdict && <Verdict value={m.verdict} />}</header>
              <p>{m.text}</p>
            </article>
          ))}
          {fw.busy && <p className="muted msg-wait" role="status">Crossing the gateways</p>}
          <div ref={logEnd} />
        </div><GradualBlur position="bottom" target="parent" height="2.5rem" strength={1.5} layers={5} zIndex={1} /></div>

        {fw.error && (
          <ErrorPanel error={fw.error} compact
            onRetry={() => { fw.setError(null); if (lastSent.current) submit(lastSent.current.value, lastSent.current.docText) }}
            onNewSession={() => fw.newSession()} />
        )}

        <form className="composer" onSubmit={(e) => { e.preventDefault(); submit() }}>
          {docOpen && (
            <label className="field"><span>Untrusted document, screened separately and datamarked</span>
              <textarea className="input" rows={3} maxLength={12000} value={doc} onChange={(e) => setDoc(e.target.value)} />
            </label>
          )}
          <label className="visually-hidden" htmlFor="chat-input">Message</label>
          <textarea id="chat-input" className="input" rows={2} maxLength={4096} placeholder="Write a prompt" value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); submit() } }} />
          <div className="row spread">
            <div className="row">
              <button type="button" className="btn btn-s" onClick={redTeam}>Red-team sample</button>
              <button type="button" className="btn btn-s" aria-pressed={docOpen} onClick={() => setDocOpen((v) => !v)}>{docOpen ? 'Remove document' : 'Attach document'}</button>
            </div>
            <div className="row">
              <span className="measured muted">{text.length}/4096</span>
              <button className="btn btn-primary" disabled={fw.busy || !text.trim()}>{fw.busy ? 'Working' : 'Send'}</button>
            </div>
          </div>
        </form>
      </section>

      <aside className="console-trace" aria-label="Verdict trace">
        <section className="panel-sec">
          <div className="row spread">
            <h2 className="h-title">Decision</h2>
            {fw.result && <span className="measured muted row-tight"><Counter value={Math.round(fw.result.latency_total_ms)} fontSize={13} intro={false} motionBlur={false} duration={0.3} bounce={0} /> ms total</span>}
          </div>
          {fw.result ? (
            <>
              <p className="reading-s"><Verdict value={outcome(fw.result)} /></p>
              <p>{explainVerdict(fw.result, fw.analysis)}</p>
              {fw.result.attack_type && fw.result.attack_type !== 'UNKNOWN' && <p className="measured muted">{fw.result.attack_type.replaceAll('_', ' ').toLowerCase()}</p>}
            </>
          ) : <p className="muted">{fw.busy ? 'Running.' : 'No request yet.'}</p>}
          <h3 className="sub">Highest severity found</h3>
          <SeverityScale value={severity} />
          {fw.verdicts.G1?.confidence != null && <PercentScale label="Gateway 1 confidence" value={fw.verdicts.G1.confidence} />}
        </section>

        <section className="panel-sec">
          <h2 className="h-title">Trace</h2>
          <Pipeline layers={fw.layers} verdicts={fw.verdicts} />
        </section>

        <section className="panel-sec">
          <h2 className="h-title">Evidence</h2>
          <Findings flags={fw.analysis?.flags} />
          {fw.analysis?.transforms?.length > 0 && (
            <>
              <h3 className="sub">What the canonicalizer undid</h3>
              <ul className="plain">{fw.analysis.transforms.map((t) => <li key={t}>{t}</li>)}</ul>
              <h3 className="sub">What the model would read</h3>
              <pre className="code">{fw.analysis.normalized}</pre>
            </>
          )}
          {reports.length > 0 && (
            <>
              <h3 className="sub">Documents</h3>
              <ul className="plain">{reports.map((r, i) => <li key={i}>{r.source}: {r.quarantined ? 'quarantined' : 'included, datamarked'}{r.reasons?.[0] ? `. ${r.reasons[0]}` : ''}</li>)}</ul>
            </>
          )}
        </section>

        <section className="panel-sec">
          <h2 className="h-title">Providers</h2>
          <Providers providers={fw.providers} />
          {fw.result?.llm_responses?.groq && (
            <details className="details">
              <summary>Compare answers</summary>
              {['groq', 'gemini', 'mistral'].map((n) => fw.result.llm_responses[n]?.text && <div key={n}><h3 className="sub">{n}</h3><p>{fw.result.llm_responses[n].text}</p></div>)}
            </details>
          )}
        </section>
      </aside>
    </main>
  )
}
