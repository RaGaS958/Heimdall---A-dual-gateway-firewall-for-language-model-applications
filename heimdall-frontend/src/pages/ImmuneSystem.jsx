import { useCallback, useEffect, useRef, useState } from 'react'
import { heat } from '../components/Charts.jsx'
import { AdminGate, Empty, ErrorPanel, PageHead, Skeleton } from '../components/ui.jsx'
import { useFetch } from '../hooks/useFetch.js'
import { BASE_URL, api } from '../lib/api.js'
import StreamingRows from '../components/motion/StreamingRows.jsx'
import Stepper, { Step } from '../components/reactbits/Stepper.jsx'

const EVENT_COLUMNS = [
  { key: 'at', header: 'Time', value: (e) => e.at, render: (e) => <span className="measured muted">{e.at}</span> },
  { key: 'type', header: 'Event', value: (e) => e.type, render: (e) => e.type.replaceAll('_', ' ').toLowerCase() },
]
const PATCH_STEP = { PATCH_APPROVED: 1, PATCH_APPLYING: 1, RULE_RELOADED: 2, RETEST_STARTED: 3, RETEST_COMPLETED: 3, PATCH_VERIFIED: 4, PATCH_VERIFICATION_FAILED: 4 }

const SEEDS = [['atk_001', 'Ignore instructions'], ['atk_002', 'DAN persona'], ['atk_003', 'Disregard training'], ['atk_004', 'Pretend AI'], ['atk_005', 'Repeat initial']]
const TECHNIQUES = {
  case_mutation: 'Case', whitespace_mutation: 'Whitespace', homoglyph_substitution: 'Homoglyph', zero_width_insertion: 'Zero-width', synonym_substitution: 'Synonym',
  base64_wrap: 'Base64', markdown_wrap: 'Markdown', json_wrap: 'JSON', sentence_reorder: 'Reorder', reverse_wrap: 'Reverse', insertion_padding: 'Padding',
}

function Workspace({ signOut }) {
  const [seeds, setSeeds] = useState(['atk_001', 'atk_002'])
  const [techs, setTechs] = useState(['homoglyph_substitution', 'base64_wrap', 'synonym_substitution'])
  const [attempts, setAttempts] = useState(36)
  const [actionError, setActionError] = useState(null)
  const [events, setEvents] = useState([])
  const lastPatch = events.find((e) => PATCH_STEP[e.type])
  const patchStep = lastPatch ? PATCH_STEP[lastPatch.type] : 0
  const patchFailed = lastPatch?.type === 'PATCH_VERIFICATION_FAILED'
  const [streamState, setStreamState] = useState('connecting')
  const [acting, setActing] = useState(null)

  const status = useFetch(() => api('/immune/status', { admin: true }), [], { interval: 5000 })
  const coverage = useFetch(() => api('/immune/coverage', { admin: true }))
  const proposals = useFetch(() => api('/immune/proposals', { admin: true }))
  const history = useFetch(() => api('/immune/history?limit=10', { admin: true }))
  const refresh = useRef(() => {})
  refresh.current = () => { status.reload({ quiet: true }); coverage.reload({ quiet: true }); proposals.reload({ quiet: true }); history.reload({ quiet: true }) }

  useEffect(() => {
    let source, stopped = false
    async function open() {
      try {
        const { token } = await api('/immune/stream-token', { method: 'POST', admin: true, body: {} })
        if (stopped) return
        source = new EventSource(`${BASE_URL}/immune/stream?token=${encodeURIComponent(token)}`)
        source.onopen = () => setStreamState('connected')
        source.onerror = () => setStreamState('disconnected')
        source.onmessage = (m) => {
          try {
            const e = JSON.parse(m.data)
            if (e.type === 'PING') return
            setEvents((prev) => [{ id: `${Date.now()}${Math.random()}`, type: e.type, at: new Date().toLocaleTimeString([], { hour12: false }), data: e.data }, ...prev].slice(0, 80))
            if (['CAMPAIGN_COMPLETED', 'CAMPAIGN_FAILED', 'PROPOSAL_CREATED', 'PATCH_VERIFIED', 'PATCH_VERIFICATION_FAILED'].includes(e.type)) refresh.current()
          } catch { /* ignore a malformed frame */ }
        }
      } catch { if (!stopped) setStreamState('disconnected') }
    }
    open()
    return () => { stopped = true; source?.close() }
  }, [])

  const start = useCallback(async () => {
    setActionError(null); setEvents([])
    try {
      await api('/immune/campaign', { method: 'POST', admin: true, body: { seed_ids: seeds, techniques: techs, n_per_technique: 1, mode: 'adaptive', max_attempts: attempts } })
      status.reload({ quiet: true })
    } catch (e) { setActionError(e) }
  }, [seeds, techs, attempts, status])

  async function decide(id, action) {
    setActing(id); setActionError(null)
    try { await api(`/immune/proposals/${id}/${action}`, { method: 'POST', admin: true, body: {} }); refresh.current() }
    catch (e) { setActionError(e) } finally { setActing(null) }
  }

  if (status.error && !status.data) return <ErrorPanel error={status.error} onRetry={() => status.reload()} onAdminKey={signOut} />

  const active = status.data?.active
  const matrix = coverage.data?.coverage || {}
  const usedTechs = [...new Set(Object.values(matrix).flatMap((v) => Object.keys(v)))]
  const items = proposals.data?.proposals || []

  return (
    <>
      <section className="panels stats-3">
        <div className="panel-sec"><p className="reading">v{status.data?.defenseVersion ?? 'n/a'}</p><p className="muted">defense version</p></div>
        <div className="panel-sec"><p className="reading">{items.length}</p><p className="muted">patches waiting for a person</p></div>
        <div className="panel-sec"><p className="reading-s">{active ? 'Campaign running' : 'Idle'}</p><p className="measured muted">{status.data?.activeCampaignId || 'no active campaign'}</p></div>
      </section>

      {actionError && <ErrorPanel compact error={actionError} onRetry={() => setActionError(null)} onAdminKey={signOut} />}

      <div className="two-col section-t">
        <section className="panel">
          <h2 className="h-title">New campaign</h2>
          <fieldset><legend>Seed attacks</legend><div className="row wrap">{SEEDS.map(([id, label]) => {
            const on = seeds.includes(id)
            return <button key={id} aria-pressed={on} className={`chip-btn ${on ? 'is-on' : ''}`} onClick={() => setSeeds((s) => on ? s.filter((x) => x !== id) : [...s, id])}>{label}</button>
          })}</div></fieldset>
          <fieldset><legend>Mutations</legend><div className="row wrap">{Object.entries(TECHNIQUES).map(([id, label]) => {
            const on = techs.includes(id)
            return <button key={id} aria-pressed={on} className={`chip-btn ${on ? 'is-on' : ''}`} onClick={() => setTechs((s) => on ? s.filter((x) => x !== id) : [...s, id])}>{label}</button>
          })}</div></fieldset>
          <label className="field"><span>Attempts, 1 to 200</span><input className="input measured" type="number" min={1} max={200} value={attempts} onChange={(e) => setAttempts(Math.min(200, Math.max(1, Number(e.target.value) || 1)))} /></label>
          <div className="row"><button className="btn btn-primary" onClick={start} disabled={active || !seeds.length || !techs.length}>{active ? 'Running' : 'Start campaign'}</button></div>
        </section>
        <section className="panel">
          <div className="row spread"><h2 className="h-title">Live log</h2><span className={`chip chip-${streamState === 'connected' ? 'ok' : streamState === 'connecting' ? 'muted' : 'accent'}`}>{{ connected: 'Streaming', connecting: 'Connecting', disconnected: 'Not streaming' }[streamState]}</span></div>
          <div className="max-h stream-log"><StreamingRows rows={events.slice(0, 40)} columns={EVENT_COLUMNS} getRowId={(e) => e.id} caption="Live campaign events" empty="Events from a running campaign appear here." /></div>
          {patchStep > 0 && (
            <div className="patch-steps">
              <Stepper step={patchStep} showFooter={false} frame={false} radius={0} width="100%" disableStepIndicators transition="fade" accentColor="#2563EB">
                <Step><p className="muted">Approved by a person.</p></Step>
                <Step><p className="muted">Rule applied and reloaded.</p></Step>
                <Step><p className="muted">Retesting the stored bypass and benign samples.</p></Step>
                <Step><p>{patchFailed ? 'Retest failed. The rule set was restored.' : 'Verified. The rule stays in force.'}</p></Step>
              </Stepper>
            </div>
          )}
        </section>
      </div>

      <section className="panel section-t">
        <h2 className="h-title">Patches awaiting approval</h2>
        {proposals.loading && !proposals.data && <Skeleton />}
        {proposals.error && <ErrorPanel compact error={proposals.error} onRetry={() => proposals.reload()} onAdminKey={signOut} />}
        {proposals.data && items.length === 0 && <Empty title="No patches waiting">A campaign proposes one when a mutation bypasses the gateway.</Empty>}
        <ul className="stack max-h">{items.map((p) => (
          <li key={p.id} className="review-item">
            <div>
              <p>{p.technique || 'Unknown technique'} against {p.seed_id || 'unknown seed'}{p.is_stale && <span className="chip chip-accent">Stale</span>}{!p.retestable && <span className="chip">Cannot be retested</span>}</p>
              <p className="muted">{p.explanation_why || p.explanation_what}</p>
              <pre className="code">{p.proposed_fix_data_parsed?.regex || JSON.stringify(p.proposed_fix_data_parsed)}</pre>
            </div>
            <div className="row">
              <button className="btn btn-primary" disabled={acting === p.id || p.is_stale || !p.retestable} title={p.retestable ? undefined : 'The bypass text from this campaign is gone. Reject this and run a new campaign.'} onClick={() => decide(p.id, 'approve')}>Apply and retest</button>
              <button className="btn" disabled={acting === p.id} onClick={() => decide(p.id, 'reject')}>Reject</button>
            </div>
          </li>
        ))}</ul>
      </section>

      <section className="panel section-t table-wrap">
        <h2 className="h-title">Bypass rate by seed and mutation</h2>
        {coverage.loading && !coverage.data && <Skeleton />}
        {coverage.data && !Object.keys(matrix).length && <Empty title="No coverage recorded">Run a campaign to fill this matrix.</Empty>}
        {Object.keys(matrix).length > 0 && (
          <>
            <table className="table matrix">
              <thead><tr><th>Seed</th>{usedTechs.map((t) => <th key={t} className="num">{TECHNIQUES[t] || t}</th>)}</tr></thead>
              <tbody>{Object.entries(matrix).map(([seed, row]) => (
                <tr key={seed}><td className="measured">{seed}</td>{usedTechs.map((t) => row[t]
                  ? <td key={t} className="num measured" style={{ background: heat(row[t].bypass_rate) }} title={`${row[t].bypasses} of ${row[t].attempts} attempts bypassed`}>{Math.round(row[t].bypass_rate * 100)}%</td>
                  : <td key={t} className="num muted">n/a</td>)}</tr>
              ))}</tbody>
            </table>
            <div className="heat-legend"><span className="measured">0%</span><i /><span className="measured">100% of attempts bypassed</span></div>
          </>
        )}
      </section>

      <section className="panel section-t table-wrap">
        <h2 className="h-title">Campaign history</h2>
        {history.data?.campaigns?.length ? (
          <table className="table"><thead><tr><th>Campaign</th><th>Status</th><th className="num">Bypasses</th></tr></thead>
            <tbody>{history.data.campaigns.map((c, i) => <tr key={c.id || i}><td className="measured">{c.id || c.campaign_id}</td><td>{c.status}</td><td className="num measured">{c.bypasses ?? c.bypass_count ?? 'n/a'}</td></tr>)}</tbody></table>
        ) : <Empty title="No campaigns recorded" />}
      </section>
    </>
  )
}

export default function ImmuneSystem() {
  return (
    <main className="container page">
      <PageHead title="Immune system" figure="Patch">Mutate known attacks, find what gets through, and propose a patch. Nothing is applied until a person approves it and a retest confirms it.</PageHead>
      <AdminGate title="Admin key required">{({ signOut }) => <Workspace signOut={signOut} />}</AdminGate>
    </main>
  )
}
