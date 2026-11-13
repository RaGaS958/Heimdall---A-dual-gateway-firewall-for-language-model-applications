import { useEffect, useRef, useState } from 'react'
import { LogoMark } from './Logo.jsx'
import { ChatText, Check, FileText, Prohibit, Robot, ShieldCheck } from './icons.js'

const INPUTS = [[ChatText, 'Prompt'], [FileText, 'Document'], [Robot, 'Model answer']]
const OUTPUTS = [[Check, 'Passed', 'ok'], [ShieldCheck, 'Fenced as data', 'cool'], [Prohibit, 'Blocked', 'bad']]
const ROWS = [10, 30, 50]

/** Layout pattern from the MotionSites "VeilGuard" firewall-flow card: inputs, connectors, a hub, verdicts.
 *  Connectors draw left to right once the card is on screen; reduced motion shows the finished state. */
export default function FlowCard() {
  const ref = useRef(null)
  const [seen, setSeen] = useState(false)
  useEffect(() => {
    const io = new IntersectionObserver(([e]) => { if (e.isIntersecting) { setSeen(true); io.disconnect() } }, { threshold: 0.5 })
    io.observe(ref.current)
    return () => io.disconnect()
  }, [])
  return (
    <div ref={ref} className={`flow ${seen ? 'is-in' : ''}`} role="img" aria-label="A prompt, a document and a model answer enter Heimdall. Each leaves as passed, fenced as data, or blocked.">
      <svg className="flow-lines flow-in" viewBox="0 0 100 60" preserveAspectRatio="none" aria-hidden="true">
        {ROWS.map((y) => <path key={y} d={`M30 ${y} C40 ${y} 38 30 44 30`} />)}
      </svg>
      <svg className="flow-lines flow-to" viewBox="0 0 100 60" preserveAspectRatio="none" aria-hidden="true">
        {ROWS.map((y, i) => <path key={y} className={`to-${OUTPUTS[i][2]}`} d={`M56 30 C62 30 60 ${y} 70 ${y}`} />)}
      </svg>
      <ul className="flow-col">{INPUTS.map(([Icon, name]) => <li key={name} className="flow-pill"><Icon size={18} aria-hidden="true" />{name}</li>)}</ul>
      <div className="flow-hub"><LogoMark size={40} /></div>
      <ul className="flow-col flow-out">{OUTPUTS.map(([Icon, name, tone], i) => <li key={name} className={`flow-pill tone-${tone}`} style={{ '--d': `${900 + i * 110}ms` }}><Icon size={18} weight="bold" aria-hidden="true" />{name}</li>)}</ul>
    </div>
  )
}
