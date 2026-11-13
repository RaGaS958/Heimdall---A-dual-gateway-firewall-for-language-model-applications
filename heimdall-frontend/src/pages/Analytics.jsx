import { useMemo } from 'react'
import { BarRows } from '../components/Charts.jsx'
import { AnalyticsBento, AnimatedBars } from '../components/motion/DataViz.jsx'
import StreamingRows from '../components/motion/StreamingRows.jsx'
import Counter from '../components/reactbits/Counter.jsx'
import { Empty, ErrorPanel, PageHead, Skeleton } from '../components/ui.jsx'
import { useStats } from '../context/StatsContext.jsx'
import { useFetch } from '../hooks/useFetch.js'
import { api } from '../lib/api.js'
import { fmtMs, fmtPct } from '../lib/layers.js'

const REQUEST_COLUMNS = [
  { key: 'at', header: 'Time', sortable: true, value: (r) => r.at, render: (r) => <span className="measured muted">{new Date(r.at).toLocaleTimeString()}</span> },
  { key: 'verdict', header: 'Outcome', sortable: true, value: (r) => r.verdict, render: (r) => r.verdict.toLowerCase() },
  { key: 'ms', header: 'Latency, ms', sortable: true, numeric: true, value: (r) => r.latencyMs },
]

export default function Analytics() {
  const { stats, clear } = useStats()
  const server = useFetch(() => api('/stats'), [], { interval: 15000 })
  const s = server.data
  const hasServerTraffic = s && s.summary.total_requests > 0
  const avg = stats.latencyCount ? stats.latencySum / stats.latencyCount : null
  const outcomes = [
    { label: 'Passed', value: stats.PASS, tone: 'ok' }, { label: 'Sanitized', value: stats.SANITIZE, tone: 'cool' },
    { label: 'Blocked', value: stats.BLOCK, tone: 'bad' }, { label: 'In review', value: stats.REVIEW, tone: 'accent' },
  ]
  const latest = useMemo(() => [...stats.recent].slice(-12).reverse(), [stats.recent])
  const attacks = Object.entries(stats.attackTypes).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k.replaceAll('_', ' ').toLowerCase(), value: v }))

  return (
    <main className="container page">
      <PageHead title="Analytics" figure="Phosphor" actions={<button className="btn" onClick={() => server.reload()}>Refresh</button>}>
        Counters since the middleware last started, and what this browser has observed.
      </PageHead>

      <section className="panels stats-3">
        {server.loading && !s && <div className="panel-sec"><Skeleton lines={2} /></div>}
        {server.error && !s && <div className="panel-sec span-all"><ErrorPanel compact error={server.error} onRetry={() => server.reload()} /></div>}
        {s && (
          <>
            <div className="panel-sec"><div className="reading"><Counter value={s.summary.total_requests} fontSize={44} motionBlur={false} /></div><p className="muted">requests through Gateway 1</p></div>
            <div className="panel-sec"><p className="reading">{hasServerTraffic ? fmtPct(s.summary.block_rate) : 'n/a'}</p><p className="muted">blocked at either gateway</p></div>
            <div className="panel-sec"><div className="reading"><Counter value={s.summary.agentic_calls} fontSize={44} motionBlur={false} /></div><p className="muted">arbiter calls</p></div>
          </>
        )}
      </section>

      <div className="section-t"><AnalyticsBento recent={stats.recent} outcomes={outcomes} /></div>

      <section className="panel section-t"><h2 className="h-title">Latest requests, this browser</h2>
        <StreamingRows rows={latest} columns={REQUEST_COLUMNS} getRowId={(r) => r.at} caption="Latest requests from this browser" empty="Requests from the Console appear here." />
      </section>

      <div className="two-col section-t">
        <section className="panel"><h2 className="h-title">Outcomes, this browser</h2>
          {stats.total ? <AnimatedBars rows={outcomes} /> : <Empty title="No requests yet" />}
        </section>
        <section className="panel"><h2 className="h-title">Attack types, this browser</h2>
          {attacks.length ? <BarRows rows={attacks} format={(v) => Math.round(v)} /> : <Empty title="No attacks classified">Only arbiter decisions carry an attack type.</Empty>}
        </section>
      </div>

      {s && (
        <section className="panel section-t table-wrap"><h2 className="h-title">Gateways since start</h2>
          <table className="table">
            <thead><tr><th>Gateway</th><th className="num">Total</th><th className="num">Blocked</th><th className="num">Sanitized</th><th className="num">Passed</th></tr></thead>
            <tbody>
              <tr><td>Gateway 1, input</td><td className="num measured">{s.gateway1.total}</td><td className="num measured">{s.gateway1.blocked}</td><td className="num measured">{s.gateway1.sanitized}</td><td className="num measured">{s.gateway1.passed}</td></tr>
              <tr><td>Gateway 2, output</td><td className="num measured">{s.gateway2.total}</td><td className="num measured">{s.gateway2.blocked}</td><td className="num measured">{s.gateway2.sanitized}</td><td className="num measured">{s.gateway2.passed}</td></tr>
            </tbody>
          </table>
        </section>
      )}
      <p className="section-t"><button className="btn btn-s" onClick={clear} disabled={!stats.total}>Clear this browser's figures</button></p>
    </main>
  )
}
