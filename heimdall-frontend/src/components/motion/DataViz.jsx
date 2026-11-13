import { useMemo, useState } from 'react'
import { motion } from 'motion/react'
import { fmtMs } from '../../lib/layers.js'
import { useReducedMotion } from '../../motion/reduced.js'
import { Empty } from '../ui.jsx'

/* Rebuilt from the published descriptions of the 21st.dev components named on each export. Every value is real. */
const TONES = { ok: 'var(--color-ok)', cool: 'var(--color-cool)', bad: 'var(--color-bad)', accent: 'var(--color-accent)' }

/** Texture as well as colour, so series stay distinct without colour vision. */
const Pattern = ({ id, tone, kind }) => (
  <pattern id={id} width="8" height="8" patternUnits="userSpaceOnUse" patternTransform={kind === 'diag' ? 'rotate(45)' : undefined}>
    <rect width="8" height="8" fill={TONES[tone]} />
    {kind !== 'solid' && <rect width={kind === 'dots' ? 3 : 2} height={kind === 'dots' ? 3 : 8} fill="var(--color-paper)" opacity="0.45" />}
  </pattern>
)
const KINDS = { ok: 'solid', cool: 'diag', bad: 'dots', accent: 'bars' }

/** 21st.dev Animated Bar Chart: springy bars with textured series and a legend that toggles them. */
export function AnimatedBars({ rows }) {
  const reduced = useReducedMotion()
  const [off, setOff] = useState({})
  const [hover, setHover] = useState(null)
  const live = rows.filter((r) => !off[r.label])
  const top = Math.max(1, ...live.map((r) => r.value))
  const W = 560, H = 230, base = H - 28, slot = W / Math.max(rows.length, 1)
  return (
    <div className="chart" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={rows.map((r) => `${r.label} ${r.value}`).join(', ')}>
        <defs>{rows.map((r) => <Pattern key={r.label} id={`tex-${r.tone}`} tone={r.tone} kind={KINDS[r.tone]} />)}</defs>
        <line x1="0" x2={W} y1={base} y2={base} className="grid" />
        {rows.map((r, i) => {
          const h = off[r.label] ? 0 : Math.max(r.value ? 3 : 0, (r.value / top) * (base - 22))
          const x = i * slot + slot * 0.18, w = slot * 0.64
          return (
            <g key={r.label} onMouseEnter={() => setHover(r)}>
              <rect x={i * slot} y="0" width={slot} height={H} fill="transparent" />
              <motion.rect x={x} width={w} fill={`url(#tex-${r.tone})`} initial={false} animate={{ y: base - h, height: h }} transition={reduced ? { duration: 0 } : { type: 'spring', stiffness: 170, damping: 22 }} />
              <text x={x + w / 2} y={base - h - 6} textAnchor="middle" className="axis">{off[r.label] ? '' : r.value}</text>
              <text x={x + w / 2} y={H - 8} textAnchor="middle" className="axis">{r.label}</text>
            </g>
          )
        })}
      </svg>
      {hover && <div className="tooltip" style={{ left: `${((rows.indexOf(hover) + 0.5) / rows.length) * 100}%` }}><span className="measured">{hover.value}</span> {hover.label.toLowerCase()}</div>}
      <div className="legend">{rows.map((r) => (
        <button key={r.label} className="legend-btn" aria-pressed={!off[r.label]} onClick={() => setOff((o) => ({ ...o, [r.label]: !o[r.label] }))}><i style={{ background: TONES[r.tone] }} />{r.label}</button>
      ))}</div>
    </div>
  )
}

const quantile = (values, q) => {
  if (!values.length) return null
  const s = [...values].sort((a, b) => a - b)
  return s[Math.min(s.length - 1, Math.floor(q * s.length))]
}

/** 21st.dev Analytics Bento: latency line with scrub, an outcome map, and percentiles, from this browser's own requests. */
export function AnalyticsBento({ recent, outcomes }) {
  const [scrub, setScrub] = useState(null)
  const values = useMemo(() => recent.map((r) => r.latencyMs), [recent])
  const W = 720, H = 220, top = Math.max(1, ...values)
  const point = (v, i) => [(i / Math.max(1, values.length - 1)) * W, H - 12 - (v / top) * (H - 28)]
  const line = values.map((v, i) => point(v, i).join(',')).join(' ')
  const total = outcomes.reduce((n, o) => n + o.value, 0)
  if (!recent.length) return <section className="panel"><Empty title="Nothing measured yet">Send prompts from the Console and each one is plotted here.</Empty></section>
  const at = scrub == null ? values.length - 1 : scrub
  const [x, y] = point(values[at], at)
  return (
    <section className="bento" aria-label="This browser's requests">
      <div className="bento-cell bento-line">
        <div className="row spread"><h2 className="h-title">Latency, this browser</h2><span className="measured">{fmtMs(values[at])}</span></div>
        <div className="chart" onMouseLeave={() => setScrub(null)} onMouseMove={(e) => {
          const r = e.currentTarget.getBoundingClientRect()
          setScrub(Math.max(0, Math.min(values.length - 1, Math.round(((e.clientX - r.left) / r.width) * (values.length - 1)))))
        }}>
          <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Latency of the last ${values.length} requests, peak ${Math.round(top)} milliseconds`}>
            <polyline points={line} fill="none" stroke="var(--color-cool)" strokeWidth="2" vectorEffect="non-scaling-stroke" />
            <line x1={x} x2={x} y1="0" y2={H} className="grid" /><rect x={x - 4} y={y - 4} width="8" height="8" fill="var(--color-accent)" />
          </svg>
        </div>
      </div>
      <div className="bento-cell">
        <h2 className="h-title">Outcome share</h2>
        <div className="treemap">{outcomes.filter((o) => o.value).map((o) => (
          <div key={o.label} className={`tm-${o.tone}`} style={{ flexGrow: o.value }}><span>{o.label}</span><span className="measured">{Math.round((o.value / total) * 100)}%</span></div>
        ))}</div>
      </div>
      <div className="bento-cell bento-stats">
        {[['Median', quantile(values, 0.5)], ['95th percentile', quantile(values, 0.95)], ['Requests', null]].map(([label, v]) => (
          <div key={label}><p className="reading-s measured">{v == null ? values.length : fmtMs(v)}</p><p className="muted">{label}</p></div>
        ))}
      </div>
    </section>
  )
}
