import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Empty, ErrorPanel, PageHead, Skeleton } from '../components/ui.jsx'
import { useFetch } from '../hooks/useFetch.js'
import { api } from '../lib/api.js'
import { AnimatedTabs } from '../components/motion/Controls.jsx'
import { ScrollProgress, Timeline } from '../components/motion/ScrollFx.jsx'
import { TextRevealMask } from '../components/motion/TextFx.jsx'
import CountUp from '../components/reactbits/CountUp.jsx'

const TABS = [['evaluation', 'Evaluation'], ['archive', 'Phase record'], ['experiments', 'Experiments'], ['compare', 'Compare']]
const ci = (v) => `${(v[0] * 100).toFixed(1)} to ${(v[1] * 100).toFixed(1)}%`

function Evaluation() {
  const { data, error, loading, reload } = useFetch(() => fetch('/data/evaluation.json').then((r) => r.json()))
  if (loading) return <Skeleton lines={6} />
  if (error) return <ErrorPanel error={error} onRetry={reload} />
  return (
    <>
      <section className="panel">
        <TextRevealMask className="h-title" text="Gateway interception, v2 against v3" />
        <div className="count-strip">{data.rows.slice(0, 4).map((r) => (
          <div key={r.name}><p className="reading-s measured"><CountUp to={r.after} duration={1.1} />/{r.n}</p><p className="muted">{r.name}</p></div>
        ))}</div>
        <p className="muted">{data.conditions}</p>
        <div className="table-wrap"><table className="table">
          <thead><tr><th>Set</th><th className="num">n</th><th className="num">v2</th><th className="num">v3</th><th className="num">v3, 95% interval</th><th className="num">McNemar p</th><th>Status</th></tr></thead>
          <tbody>{data.rows.map((r) => (
            <tr key={r.name}><td>{r.name}</td><td className="num measured">{r.n}</td><td className="num measured">{r.before}</td><td className="num measured">{r.after}</td><td className="num measured">{ci(r.after_ci)}</td><td className="num measured">{r.mcnemar_p < 0.001 ? r.mcnemar_p.toExponential(1) : r.mcnemar_p.toFixed(3)}</td><td className="muted">{r.status}</td></tr>
          ))}</tbody>
        </table></div>
      </section>
      <section className="panel section-t">
        <h2 className="h-title">What these numbers do not show</h2>
        <ul className="plain">{data.limits.map((l) => <li key={l}>{l}</li>)}</ul>
      </section>
    </>
  )
}

function Archive() {
  const { data, error, loading, reload } = useFetch(() => fetch('/data/evaluation.json').then((r) => r.json()))
  if (loading) return <Skeleton lines={6} />
  if (error) return <ErrorPanel error={error} onRetry={reload} />
  return (
    <section className="panel">
      <h2 className="h-title">Published record, Phase 14</h2>
      <p className="muted">Status of the original manuscript: READY_WITH_LIMITATIONS. Numbers below describe the v2 code and are reproduced from its evidence ledger.</p>
      <Timeline items={data.phase_record.map((p) => ({ label: p.phase, body: p.finding }))} />
    </section>
  )
}

function Experiments() {
  const list = useFetch(() => api('/research/experiments?limit=200'))
  const [selected, setSelected] = useState(null)
  const summary = useFetch(() => api(`/research/experiments/${selected}/summary`), [selected], { enabled: !!selected })
  if (list.loading) return <Skeleton lines={8} />
  if (list.error) return <ErrorPanel error={list.error} onRetry={() => list.reload()} />
  const rows = list.data?.experiments || []
  if (!rows.length) return <section className="panel"><Empty title="The registry is empty">Run an experiment from research/ to populate it.</Empty></section>
  const metrics = summary.data?.metrics || {}
  return (
    <div className="lab-grid">
      <section className="panel table-wrap max-h">
        <table className="table">
          <thead><tr><th>Experiment</th><th>Status</th></tr></thead>
          <tbody>{rows.map((r) => (
            <tr key={r.experiment_id} tabIndex={0} className={`clickable ${selected === r.experiment_id ? 'is-open' : ''}`} onClick={() => setSelected(r.experiment_id)} onKeyDown={(e) => e.key === 'Enter' && setSelected(r.experiment_id)}>
              <td><span className="clip-inline">{r.name || r.experiment_id}</span></td><td>{r.status === 'INVALIDATED' ? <span className="chip chip-accent">Invalidated</span> : r.status.toLowerCase()}</td>
            </tr>
          ))}</tbody>
        </table>
      </section>
      <section className="panel">
        {!selected && <Empty title="Select an experiment">Metrics are read from its stored results.</Empty>}
        {selected && summary.loading && <Skeleton />}
        {selected && summary.error && <ErrorPanel compact error={summary.error} onRetry={() => summary.reload()} />}
        {summary.data && (
          <>
            <h2 className="h-title measured">{selected}</h2>
            <table className="table table-tight"><thead><tr><th>Metric</th><th className="num">Value</th><th className="num">n</th></tr></thead>
              <tbody>{Object.entries(metrics).map(([k, m]) => <tr key={k}><td>{k}</td><td className="num measured">{m.value == null ? 'n/a' : Number(m.value).toFixed(3)}</td><td className="num measured">{m.n ?? 'n/a'}</td></tr>)}</tbody></table>
          </>
        )}
      </section>
    </div>
  )
}

function Compare() {
  const list = useFetch(() => api('/research/experiments?limit=200'))
  const [a, setA] = useState(''), [b, setB] = useState('')
  const result = useFetch(() => api(`/research/comparison?exp_a=${encodeURIComponent(a)}&exp_b=${encodeURIComponent(b)}`), [a, b], { enabled: !!(a && b && a !== b) })
  if (list.loading) return <Skeleton lines={4} />
  if (list.error) return <ErrorPanel error={list.error} onRetry={() => list.reload()} />
  const options = (list.data?.experiments || []).map((r) => <option key={r.experiment_id} value={r.experiment_id}>{r.name || r.experiment_id}</option>)
  const r = result.data
  return (
    <section className="panel">
      <div className="row">
        <label className="field grow"><span>Experiment A</span><select className="input" value={a} onChange={(e) => setA(e.target.value)}><option value="">Choose</option>{options}</select></label>
        <label className="field grow"><span>Experiment B</span><select className="input" value={b} onChange={(e) => setB(e.target.value)}><option value="">Choose</option>{options}</select></label>
      </div>
      {result.loading && <Skeleton />}
      {result.error && <ErrorPanel compact error={result.error} onRetry={() => result.reload()} />}
      {!r && !result.loading && <Empty title="Pick two experiments">The configurations are checked for comparability first.</Empty>}
      {r && (
        <>
          {r.warning && <div className="error-panel is-compact" role="status"><p className="error-why">{r.warning}</p></div>}
          <div className="table-wrap"><table className="table table-tight"><thead><tr><th>Metric</th><th className="num">A</th><th className="num">B</th><th className="num">B minus A</th></tr></thead>
            <tbody>{Object.entries(r.metric_differences).map(([k, m]) => <tr key={k}><td>{k}</td><td className="num measured">{m.exp_a_value ?? 'n/a'}</td><td className="num measured">{m.exp_b_value ?? 'n/a'}</td><td className="num measured">{m.difference ?? 'n/a'}</td></tr>)}</tbody></table></div>
        </>
      )}
    </section>
  )
}

export default function Research() {
  const [params, setParams] = useSearchParams()
  const tab = params.get('tab') || 'evaluation'
  return (
    <main className="container page">
      <ScrollProgress />
      <PageHead title="Research" figure="Loupe">What was measured, how, and where it stops being evidence.</PageHead>
      <AnimatedTabs tabs={TABS} value={tab} onChange={(id) => setParams({ tab: id })} label="Research sections" />
      {tab === 'evaluation' && <Evaluation />}
      {tab === 'archive' && <Archive />}
      {tab === 'experiments' && <Experiments />}
      {tab === 'compare' && <Compare />}
    </main>
  )
}
