import { LAYERS, fmtMs } from '../lib/layers.js'

const WORD = {
  idle: 'Waiting', running: 'Running', pass: 'Clear', miss: 'No match', flag: 'Flagged', block: 'Blocked',
  sanitized: 'Cleaned', sanitize: 'Sanitized', disabled: 'Off', unavailable: 'Unreachable', fallback_decision: 'Fallback',
}
const TONE = { flag: 'accent', block: 'bad', sanitize: 'cool', sanitized: 'cool', pass: 'ok', miss: 'ok', unavailable: 'accent' }

/** The verdict trace: each layer on one spine, in execution order, with its measured cost. */
export function Pipeline({ layers, verdicts }) {
  const groups = [['G1', 'Gateway 1, before the model'], ['G2', 'Gateway 2, before the person']]
  return (
    <div className="trace">
      {groups.map(([gateway, title]) => (
        <section key={gateway}>
          <h3 className="trace-head"><span>{title}</span>{verdicts?.[gateway] && <span className="measured">{verdicts[gateway].verdict}</span>}</h3>
          <ol className="trace-list">
            {LAYERS.filter((l) => l.gateway === gateway).map((layer) => {
              const state = layers[layer.id] || { status: 'idle' }
              return (
                <li key={layer.id} className={`trace-row tone-${TONE[state.status] || 'idle'} ${state.status === 'running' ? 'is-running' : ''}`}>
                  <span className="measured trace-id">{layer.id}</span>
                  <span className="trace-name">{layer.name}</span>
                  <span className="trace-status">{WORD[state.status] || state.status}</span>
                  <span className="measured trace-ms">{state.latency != null ? fmtMs(state.latency) : ''}</span>
                  {state.detail && <span className="trace-detail">{state.detail}</span>}
                </li>
              )
            })}
          </ol>
        </section>
      ))}
    </div>
  )
}
