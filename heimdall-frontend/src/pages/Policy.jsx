import { useState } from 'react'
import { AdminGate, Empty, ErrorPanel, PageHead, PercentScale, Skeleton } from '../components/ui.jsx'
import { BarRows } from '../components/Charts.jsx'
import { useFetch } from '../hooks/useFetch.js'
import { api } from '../lib/api.js'
import { fmtPct } from '../lib/layers.js'

function Simulator({ policy, signOut }) {
  const [state, setState] = useState({ busy: false, error: null, result: null })
  async function run() {
    setState({ busy: true, error: null, result: null })
    try { setState({ busy: false, error: null, result: await api('/policy/simulate', { method: 'POST', admin: true, body: { policy_name: policy, corpus: 'both' } }) }) }
    catch (error) { setState({ busy: false, error, result: null }) }
  }
  const r = state.result
  return (
    <>
      <button className="btn btn-primary" onClick={run} disabled={state.busy}>{state.busy ? 'Running' : `Simulate ${policy}`}</button>
      {state.error && <ErrorPanel compact error={state.error} onRetry={run} onAdminKey={signOut} />}
      {r && (
        <div className="section-t">
          <PercentScale label={`Attacks escalated, ${r.attacks} cases`} value={r.detection_rate} />
          <PercentScale label={`Benign escalated, ${r.benign} cases`} value={r.false_positive_rate} />
          <p className="measured muted">Project corpora, deterministic layers only. {fmtPct(r.detection_rate)} attacks, {fmtPct(r.false_positive_rate)} benign.</p>
          <h3 className="sub">By family</h3>
          <BarRows max={1} format={(v) => `${Math.round(v * 100)}`} unit="%" rows={Object.entries(r.per_family_breakdown).map(([k, v]) => ({ label: k.replaceAll('_', ' ').toLowerCase(), value: v.total ? v.detected / v.total : 0 }))} />
        </div>
      )}
    </>
  )
}

export default function Policy() {
  const list = useFetch(() => api('/policies'))
  const [active, setActive] = useState(() => localStorage.getItem('heimdall_active_policy') || 'default')
  const policies = list.data?.policies || []
  const selected = policies.find((p) => p.name === active) || policies[0]

  function choose(name) {
    setActive(name)
    localStorage.setItem('heimdall_active_policy', name)
  }

  return (
    <main className="container page">
      <PageHead title="Policies" figure="Branches">A policy tunes thresholds per deployment. Browsers can select only policies at least as strict as the default.</PageHead>
      {list.loading && !list.data && <Skeleton lines={4} />}
      {list.error && <ErrorPanel error={list.error} onRetry={() => list.reload()} />}
      {list.data && !policies.length && <Empty title="No policies found">Add YAML files to config/policies.</Empty>}
      {selected && (
        <div className="two-col">
          <section className="panel">
            <h2 className="h-title">Available</h2>
            <ul className="stack">{policies.map((p) => (
              <li key={p.name} className={`policy ${p.name === selected.name ? 'is-on' : ''}`}>
                <div><p className="f500">{p.name} <span className="measured muted">v{p.version}</span></p><p className="muted">{p.description}</p></div>
                <button className="btn btn-s" aria-pressed={p.name === active} onClick={() => choose(p.name)}>{p.name === active ? 'Active' : 'Use'}</button>
              </li>
            ))}</ul>
            <h3 className="sub">Overrides in {selected.name}</h3>
            {Object.keys(selected.overrides).length ? (
              <table className="table table-tight"><tbody>{Object.entries(selected.overrides).map(([k, v]) => <tr key={k}><td>{k.replaceAll('_', ' ')}</td><td className="num measured">{String(v)}</td></tr>)}</tbody></table>
            ) : <p className="muted">Uses the global thresholds.</p>}
          </section>
          <section className="panel"><h2 className="h-title">Simulate against the corpora</h2>
            <AdminGate title="Admin key required">{({ signOut }) => <Simulator policy={selected.name} signOut={signOut} />}</AdminGate>
          </section>
        </div>
      )}
    </main>
  )
}
