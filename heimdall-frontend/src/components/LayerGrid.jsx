import { LAYERS } from '../lib/layers.js'
import { Brain, Crosshair, Database, Eraser, Key, LinkBreak, MagnifyingGlass, Robot, Scales, UserFocus } from './icons.js'

const ICON = { L0: Database, L2: Eraser, L1: MagnifyingGlass, L3: Brain, L4: Crosshair, L5: Scales, O1: Database, O2: Key, O3: UserFocus, O4: LinkBreak, O5: Scales }
const ARBITERS = new Set(['L5', 'O5'])

function Gateway({ id, title, when }) {
  const layers = LAYERS.filter((l) => l.gateway === id)
  const arbiter = layers.find((l) => ARBITERS.has(l.id))
  return (
    <section className="gate-block" aria-label={title}>
      <header className="gate-head"><h3>{title}</h3><span className="label">{when}</span></header>
      <ol className="gate-cards">
        {layers.filter((l) => !ARBITERS.has(l.id)).map((layer) => {
          const Icon = ICON[layer.id]
          return (
            <li key={layer.id} className="gate-card">
              <div className="gate-card-top"><span className="measured">{layer.id}</span><Icon size={20} aria-hidden="true" /></div>
              <p className="gate-name">{layer.name}</p>
              <p className="muted">{layer.job}</p>
            </li>
          )
        })}
      </ol>
      <div className="gate-arbiter">
        <Scales size={20} aria-hidden="true" />
        <p><b>{arbiter.id} {arbiter.name}.</b> {arbiter.job}.</p>
        <span className="chip chip-muted">Only when flagged</span>
      </div>
    </section>
  )
}

/** The layer map from the original Heimdall home page, redrawn from the live layer list in lib/layers.js. */
export default function LayerGrid() {
  return (
    <div className="gates">
      <Gateway id="G1" title="Gateway 1" when="Before the model" />
      <div className="gate-models"><Robot size={20} aria-hidden="true" /><p><b>Three models answer in parallel.</b> Groq, Gemini and Mistral receive the hardened prompt.</p></div>
      <Gateway id="G2" title="Gateway 2" when="Before the person" />
    </div>
  )
}
