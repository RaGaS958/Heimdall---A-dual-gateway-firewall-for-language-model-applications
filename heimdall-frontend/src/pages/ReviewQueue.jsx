import { useState } from 'react'
import { AdminGate, Empty, ErrorPanel, Findings, PageHead, PercentScale, Skeleton } from '../components/ui.jsx'
import { useFetch } from '../hooks/useFetch.js'
import { api } from '../lib/api.js'
import AnimatedList from '../components/reactbits/AnimatedList.jsx'

function Queue({ signOut }) {
  const queue = useFetch(() => api('/review/queue?status=pending', { admin: true }), [], { interval: 10000 })
  const [notes, setNotes] = useState({})
  const [acting, setActing] = useState(null)
  const [error, setError] = useState(null)
  const [done, setDone] = useState([])

  async function decide(item, decision) {
    setActing(item.id); setError(null)
    try {
      const out = await api(`/review/${item.id}/decide`, { method: 'POST', admin: true, body: { decision, note: notes[item.id] || '' } })
      setDone((d) => [{ id: item.id, decision, output: out.output_verdict, at: new Date().toLocaleTimeString([], { hour12: false }) }, ...d].slice(0, 12))
      queue.reload({ quiet: true })
    } catch (e) { setError(e) } finally { setActing(null) }
  }

  if (queue.loading && !queue.data) return <Skeleton lines={5} />
  if (queue.error && !queue.data) return <ErrorPanel error={queue.error} onRetry={() => queue.reload()} onAdminKey={signOut} />
  const items = queue.data?.items || []

  return (
    <>
      {error && <ErrorPanel compact error={error} onRetry={() => { setError(null); queue.reload() }} onAdminKey={signOut} />}
      {items.length === 0 && <section className="panel"><Empty title="The queue is clear">Requests a person has to decide wait here.</Empty></section>}
      <ul className="stack">{items.map((item) => (
        <li key={item.id} className="panel review-card">
          <div className="review-main">
            <h2 className="h-title">Prompt under review</h2>
            <p className="review-why"><span className={`chip ${/no verdict/i.test(item.review_reason || '') ? 'chip-accent' : /flag as an attack/i.test(item.review_reason || '') ? 'chip-bad' : 'chip-cool'}`}>{holdKind(item.review_reason)}</span> {item.review_reason || 'Arbiter unsure'}</p>
            <pre className="code">{item.original_input}</pre>
            {!/no verdict/i.test(item.review_reason || '') && <>
              <p><b className="f500">Arbiter:</b> {item.agentic_reason || 'No reason given.'}</p>
              <PercentScale label="Arbiter confidence" value={item.agentic_confidence} />
            </>}
            <label className="field"><span>Reviewer note, stored with the decision</span>
              <input className="input" maxLength={1000} value={notes[item.id] || ''} onChange={(e) => setNotes((n) => ({ ...n, [item.id]: e.target.value }))} /></label>
            <div className="row">
              <button className="btn btn-primary" disabled={acting === item.id} onClick={() => decide(item, 'approve')}>Approve, then screen the answer</button>
              <button className="btn" disabled={acting === item.id} onClick={() => decide(item, 'reject')}>Reject as attack</button>
            </div>
          </div>
          <div>
            <h3 className="sub">Evidence</h3>
            <Findings flags={(item.flags_summary || []).map((f) => ({ severity: f.sev, families: f.families, evidence: f.evidence }))} />
            <p className="measured muted">{new Date(item.timestamp * 1000).toLocaleString()}</p>
          </div>
        </li>
      ))}</ul>
      {done.length > 0 && (
        <section className="panel section-t"><h2 className="h-title">Decided in this tab</h2>
          <AnimatedList items={done} frame={false} radius={0} width="100%" maxHeight={320} showGradients={false} selectOnHover={false} enableArrowNavigation={false} animateOnce renderItem={(d) => <div className="trail-row"><span className="measured muted">{d.at}</span><span className="reviewer">You</span><span>{d.decision === 'approve' ? `approved; answer ${String(d.output).toLowerCase()}` : 'rejected as attack'}</span></div>} />
        </section>
      )}
    </>
  )
}

function holdKind(reason = '') {
  if (/no verdict/i.test(reason)) return 'Arbiter failed'
  if (/flag as an attack/i.test(reason)) return 'Disagreement'
  return 'Unsure'
}

export default function ReviewQueue() {
  return (
    <main className="container page">
      <PageHead title="Review queue" figure="Riffle">A person decides when the arbiter is unsure, when it gives no verdict, or when it clears a request the fixed layers flag as an attack. Nothing is answered until then. Decisions become labelled data and never rewrite the detection corpus.</PageHead>
      <AdminGate title="Admin key required">{({ signOut }) => <Queue signOut={signOut} />}</AdminGate>
    </main>
  )
}
