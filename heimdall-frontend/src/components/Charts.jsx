import { useState } from 'react'

/** Horizontal bars for a handful of labelled values, with a zero baseline and an explicit maximum. */
export function BarRows({ rows, max, unit = '', format = (v) => v }) {
  const top = max ?? Math.max(1, ...rows.map((r) => r.value))
  return (
    <div className="bars" role="table">
      {rows.map((row) => (
        <div className="bar-row" role="row" key={row.label} title={`${row.label}: ${format(row.value)}${unit}`}>
          <span role="cell" className="bar-label">{row.label}</span>
          <span role="cell" className="bar-track"><span className={`bar-fill ${row.tone ? `fill-${row.tone}` : ''}`} style={{ transform: `scaleX(${top ? row.value / top : 0})` }} /></span>
          <span role="cell" className="measured bar-value">{format(row.value)}{unit}</span>
        </div>
      ))}
      <div className="bar-axis measured" aria-hidden="true"><span>0</span><span>{format(top / 2)}{unit}</span><span>{format(top)}{unit}</span></div>
    </div>
  )
}

/** Per-request columns on a labelled millisecond axis, coloured by outcome. */
export function LatencyColumns({ points }) {
  const [hover, setHover] = useState(null)
  const W = 1100, H = 240, pad = { l: 48, r: 8, t: 10, b: 26 }
  const top = Math.max(1, ...points.map((p) => p.latencyMs))
  const nice = Math.ceil(top / 10 ** Math.floor(Math.log10(top))) * 10 ** Math.floor(Math.log10(top))
  const innerW = W - pad.l - pad.r, innerH = H - pad.t - pad.b
  const step = innerW / Math.max(points.length, 20)
  const fill = { BLOCK: 'var(--color-bad)', SANITIZE: 'var(--color-cool)', REVIEW: 'var(--color-accent)', PASS: 'var(--color-ok)' }
  const ticks = [0, 0.5, 1]
  return (
    <div className="chart" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Latency of the last ${points.length} requests in milliseconds`}>
        {ticks.map((t) => {
          const y = pad.t + innerH * (1 - t)
          return <g key={t}><line x1={pad.l} x2={W - pad.r} y1={y} y2={y} className="grid" /><text x={pad.l - 6} y={y + 3} textAnchor="end" className="axis">{Math.round(nice * t)}</text></g>
        })}
        <text x={pad.l} y={H - 6} className="axis">oldest</text>
        <text x={W - pad.r} y={H - 6} textAnchor="end" className="axis">latest, ms per request</text>
        {points.map((p, i) => {
          const h = Math.max(1.5, (p.latencyMs / nice) * innerH)
          return (
            <g key={i} onMouseEnter={() => setHover({ ...p, i, x: pad.l + i * step })}>
              <rect x={pad.l + i * step} y={pad.t} width={step} height={innerH} fill="transparent" />
              <rect x={pad.l + i * step + 1} y={pad.t + innerH - h} width={Math.max(2, step - 2)} height={h} fill={fill[p.verdict]} />
            </g>
          )
        })}
      </svg>
      {hover && (
        <div className="tooltip" style={{ left: `${(hover.x / W) * 100}%` }}>
          <span className="measured">{Math.round(hover.latencyMs)} ms</span> {hover.verdict.toLowerCase()}, {new Date(hover.at).toLocaleTimeString()}
        </div>
      )}
      <div className="legend">
        {Object.entries(fill).map(([k, c]) => <span key={k}><i style={{ background: c }} />{k[0] + k.slice(1).toLowerCase()}</span>)}
      </div>
    </div>
  )
}

/** Sequential single-hue cell for a matrix of rates, 0 to 100 percent. Capped at 70% red so navy figures stay above 4.5:1. */
export const heat = (rate) => `color-mix(in oklab, var(--color-red) ${Math.round(rate * 70)}%, var(--color-paper-2))`
