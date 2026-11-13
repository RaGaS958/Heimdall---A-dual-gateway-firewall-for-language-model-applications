import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Figure } from './Figure.jsx'
import { getAdminKey, setAdminKey } from '../lib/api.js'
import { PROVIDER_ERRORS, explain } from '../lib/errors.js'
import { SEVERITY_BANDS, fmtMs } from '../lib/layers.js'

export function Skeleton({ lines = 3, label = 'Loading' }) {
  return (
    <div className="skeleton" role="status" aria-label={label}>
      {Array.from({ length: lines }, (_, i) => <span key={i} style={{ width: `${92 - i * 14}%` }} />)}
    </div>
  )
}

export function Empty({ title, children, action }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <p className="muted">{children}</p>}
      {action}
    </div>
  )
}

function useCountdown(seconds) {
  const [left, setLeft] = useState(seconds || 0)
  useEffect(() => {
    setLeft(seconds || 0)
    if (!seconds) return undefined
    const id = setInterval(() => setLeft((v) => (v <= 1 ? (clearInterval(id), 0) : v - 1)), 1000)
    return () => clearInterval(id)
  }, [seconds])
  return left
}

/** A failure says what broke, why, and offers the one action that fixes it. */
export function ErrorPanel({ error, onRetry, onNewSession, onAdminKey, compact = false }) {
  const info = explain(error)
  const left = useCountdown(error?.retryAfter)
  if (!info) return null
  return (
    <div className={`error-panel ${compact ? 'is-compact' : ''}`} role="alert">
      <div>
        <p className="error-title">{info.title}</p>
        <p className="error-why">{info.why}</p>
        {error.hint && <p className="error-hint">{error.hint}</p>}
        {error.incident && <p className="measured muted">incident {error.incident}</p>}
        {left > 0 && <p className="measured">Available again in {left} s</p>}
        {error.providers && (
          <table className="table table-tight">
            <thead><tr><th>Provider</th><th>Status</th><th>What to do</th></tr></thead>
            <tbody>{Object.entries(error.providers).map(([name, code]) => {
              const [label, fix] = PROVIDER_ERRORS[code] || [code || 'Unknown', '']
              return <tr key={name}><td>{name}</td><td>{label}</td><td className="muted">{fix}</td></tr>
            })}</tbody>
          </table>
        )}
      </div>
      <div className="error-actions">
        {info.action === 'retry' && onRetry && <button className="btn" onClick={onRetry}>Try again</button>}
        {info.action === 'wait' && onRetry && <button className="btn" onClick={onRetry} disabled={left > 0}>Try again</button>}
        {info.action === 'newSession' && onNewSession && <button className="btn btn-primary" onClick={onNewSession}>Start a new session</button>}
        {info.action === 'reconnect' && onRetry && <button className="btn" onClick={onRetry}>Reconnect</button>}
        {info.action === 'adminKey' && onAdminKey && <button className="btn btn-primary" onClick={onAdminKey}>Change admin key</button>}
      </div>
    </div>
  )
}

/** Holds the key in this tab only; a page never ships with a default credential. */
export function AdminGate({ title, children }) {
  const [key, setKey] = useState(getAdminKey())
  const [draft, setDraft] = useState('')
  if (key) return children({ signOut: () => { setAdminKey(''); setKey('') } })
  return (
    <section className="panel gate">
      <h2>{title}</h2>
      <p className="muted">Enter the ADMIN_KEY set on the middleware. It stays in this browser tab and is cleared when the tab closes.</p>
      <form className="row" onSubmit={(e) => { e.preventDefault(); setAdminKey(draft.trim()); setKey(draft.trim()) }}>
        <label className="field grow"><span>Admin key</span>
          <input className="input measured" type="password" autoComplete="off" value={draft} onChange={(e) => setDraft(e.target.value)} />
        </label>
        <button className="btn btn-primary" disabled={!draft.trim()}>Unlock</button>
      </form>
    </section>
  )
}

const VERDICT_TONE = { PASS: 'ok', SANITIZE: 'cool', BLOCK: 'bad', REVIEW: 'accent', PENDING: 'accent', SKIPPED: 'muted' }
const VERDICT_WORD = { PASS: 'Passed', SANITIZE: 'Sanitized', BLOCK: 'Blocked', REVIEW: 'In review', PENDING: 'In review', SKIPPED: 'Skipped' }

export function Verdict({ value }) {
  if (!value) return null
  return <span className={`chip chip-${VERDICT_TONE[value] || 'muted'}`}>{VERDICT_WORD[value] || value}</span>
}

/** The product's fixed 1 to 10 severity ruler, with bands, ticks and an optional marker. */
export function SeverityScale({ value = null, showLegend = false }) {
  const pct = (n) => ((n - 0.5) / 10) * 100
  return (
    <figure className="scale" aria-label={value ? `Severity ${value} of 10` : 'Severity scale from 1 to 10'}>
      <div className="scale-track">
        {SEVERITY_BANDS.map((b) => (
          <span key={b.name} className={`scale-band band-${b.tone}`} style={{ left: `${(b.from - 1) * 10}%`, width: `${(b.to - b.from + 1) * 10}%` }} />
        ))}
        {value > 0 && <span className="scale-marker" style={{ left: `${pct(value)}%` }}><b className="measured">{value}</b></span>}
      </div>
      <div className="scale-ticks" aria-hidden="true">
        {Array.from({ length: 10 }, (_, i) => <span key={i} className="measured">{i + 1}</span>)}
      </div>
      <div className="scale-names" aria-hidden="true">
        {SEVERITY_BANDS.map((b) => <span key={b.name} style={{ gridColumn: `${b.from} / ${b.to + 1}` }}>{b.name}</span>)}
      </div>
      {showLegend && (
        <figcaption className="scale-legend">
          {SEVERITY_BANDS.map((b) => (
            <div key={b.name}>
              <p><span className={`swatch band-${b.tone}`} /> {b.name} <span className="measured muted">{b.from} to {b.to}</span></p>
              <p className="muted">{b.effect}</p>
            </div>
          ))}
        </figcaption>
      )}
    </figure>
  )
}

/** A 0 to 100 percent ruler for any probability-like reading. */
export function PercentScale({ value, label, threshold }) {
  const pct = value == null ? null : Math.max(0, Math.min(1, value)) * 100
  return (
    <figure className="pscale">
      <figcaption><span>{label}</span><span className="measured">{pct == null ? 'n/a' : `${pct.toFixed(0)}%`}</span></figcaption>
      <div className="pscale-track">
        {pct != null && <span className="pscale-fill" style={{ transform: `scaleX(${pct / 100})` }} />}
        {threshold != null && <span className="pscale-limit" style={{ left: `${threshold * 100}%` }} title={`Threshold ${Math.round(threshold * 100)}%`} />}
      </div>
      <div className="pscale-ticks measured" aria-hidden="true"><span>0</span><span>50</span><span>100</span></div>
    </figure>
  )
}

export function Providers({ providers }) {
  const names = ['groq', 'gemini', 'mistral'].filter((n) => providers?.[n])
  if (!names.length) return <Empty title="No provider results yet">They appear after Gateway 1 clears the prompt.</Empty>
  return (
    <table className="table table-tight">
      <thead><tr><th>Provider</th><th>Result</th><th className="num">Latency</th><th>Model</th></tr></thead>
      <tbody>{names.map((name) => {
        const p = providers[name]
        const [label, fix] = PROVIDER_ERRORS[p.error_code] || []
        return (
          <tr key={name}>
            <td>{name}</td>
            <td>{p.ok ? 'Answered' : <span title={fix}>{p.error === 'Blocked by Heimdall (G2)' ? 'Blocked by Gateway 2' : label || 'Failed'}</span>}</td>
            <td className="num measured">{p.latency_ms ? fmtMs(p.latency_ms) : 'n/a'}</td>
            <td className="measured muted">{p.model || 'n/a'}</td>
          </tr>
        )
      })}</tbody>
    </table>
  )
}

export function Findings({ flags }) {
  if (!flags?.length) return <p className="muted">No layer raised a finding.</p>
  return (
    <ul className="findings">
      {flags.map((f, i) => (
        <li key={i}>
          <span className="measured finding-sev">{f.severity}</span>
          <div><p>{f.families?.[0]?.replaceAll('_', ' ').toLowerCase() || 'signal'}</p><p className="measured muted evidence">{f.evidence}</p></div>
        </li>
      ))}
    </ul>
  )
}

/** Every tool page opens the same way: title, one sentence, actions, and a Hairline figure from the shared set. */
export function PageHead({ title, children, actions, figure, figureLabel }) {
  return (
    <header className="page-head">
      <div className="page-head-copy"><h1>{title}</h1>{children && <p className="lead muted">{children}</p>}</div>
      <div className="page-head-side">
        {actions && <div className="row">{actions}</div>}
        {figure && <Figure name={figure} label={figureLabel || `${title} illustration`} intensity={0.6} />}
      </div>
    </header>
  )
}

export const TextLink = ({ to, children }) => <Link className="text-link" to={to}>{children}</Link>
