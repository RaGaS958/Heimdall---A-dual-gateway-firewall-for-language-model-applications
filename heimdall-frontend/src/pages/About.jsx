import { Link } from 'react-router-dom'
import { PageHead, SeverityScale } from '../components/ui.jsx'
import { LAYERS } from '../lib/layers.js'
import ScrollHighlight from '../components/motion/ScrollHighlight.jsx'
import { FullScreenScroll, ScrollOutline, ScrollProgress, TracingBeam } from '../components/motion/ScrollFx.jsx'
import { TextRevealMask } from '../components/motion/TextFx.jsx'
import AnimatedContent from '../components/reactbits/AnimatedContent.jsx'
import GlareHover from '../components/reactbits/GlareHover.jsx'
import ScrollReveal from '../components/reactbits/ScrollReveal.jsx'

const THREATS = [
  ['Direct injection', 'The user tells the model to drop its rules.', 'L1, L2, L3, L4, arbiter'],
  ['Hidden encodings', 'Unicode tags, homoglyphs, Base64 and similar disguises.', 'L2 canonicalizer, then every rule on every view'],
  ['Indirect injection', 'Instructions planted in a page, email or document.', 'Document screening, datamarking'],
  ['Prompt extraction', 'Getting the system message out of the model.', 'Hierarchy, canary, O2 overlap check'],
  ['Data exfiltration', 'An answer that leaks through an auto-loading link.', 'O4 strips active content'],
  ['Arbiter manipulation', 'Talking the judging model into clearing an attack.', 'Encoded evidence, random boundary, deterministic floor'],
]

const LIMITS = [
  'No detector stops every prompt injection. Heimdall reduces exposure and makes decisions inspectable.',
  'On the sealed external test, 85 of 808 third-party attacks still passed the deterministic layers.',
  'An attack that only makes sense inside one application cannot be recognised by a gateway that does not know that application.',
  "The arbiter's semantic accuracy against adaptive attacks has not been measured end to end.",
  'Rate limits and session locks are shared through Redis. Per-session behaviour counters are still held by each instance.',
]

const OUTLINE = [
  { id: 'threats', label: 'What it defends against' }, { id: 'layers', label: 'The layers' },
  { id: 'severity', label: 'How severity works' }, { id: 'limits', label: 'Known limits' }, { id: 'credits', label: 'Credits' },
]

export default function About() {
  return (
    <main className="container page">
      <ScrollProgress />
      <PageHead title="About Heimdall" figure="Vault">A dual-gateway firewall for language-model applications, built as a research prototype with an audited evaluation record.</PageHead>
      <ScrollHighlight className="about-statement" text="A prompt can hide its meaning from a filter and still reach the model intact. Heimdall reads every form of it first, and checks the answer on the way out." />

      <div className="about-grid">
        <aside className="about-rail"><ScrollOutline items={OUTLINE} /></aside>
        <div>
          <section id="threats" className="section-t">
            <TextRevealMask text="What it defends against" />
            <div className="about-reveal"><ScrollReveal baseOpacity={0.62} enableBlur={false} baseRotation={0} textClassName="lead-scroll">Six kinds of attack, each with a named place in the pipeline where it is handled.</ScrollReveal></div>
            <FullScreenScroll label="Threats" slides={THREATS.map(([title, body, meta]) => ({ title, body, meta }))} />
          </section>

          <section id="layers" className="section-t">
            <TextRevealMask text="The layers" />
            <TracingBeam>
              <div className="table-wrap"><table className="table">
                <thead><tr><th>Layer</th><th>Name</th><th>Job</th></tr></thead>
                <tbody>{LAYERS.map((l) => <tr key={l.gateway + l.id}><td className="measured">{l.id}</td><td>{l.name}</td><td className="muted">{l.job}</td></tr>)}</tbody>
              </table></div>
            </TracingBeam>
          </section>

          <section id="severity" className="section-t">
            <AnimatedContent distance={36} duration={0.7} ease="power3.out" threshold={0.15}>
              <h2>How severity works</h2>
              <SeverityScale showLegend />
            </AnimatedContent>
          </section>

          <section id="limits" className="section-t">
            <TextRevealMask text="Known limits" />
            <ol className="limits">
              {LIMITS.map((text, i) => <li key={text}><span className="measured" aria-hidden="true">{String(i + 1).padStart(2, '0')}</span><p>{text}</p></li>)}
            </ol>
            <p className="section-t">
              <GlareHover className="glare-inline" width="fit-content" height="auto" borderRadius="2px" glareOpacity={0.25} rimGlint={false}>
                <Link className="btn btn-primary" to="/research">Read the evaluation</Link>
              </GlareHover>
            </p>
          </section>

          <section id="credits" className="section-t">
            <h2>Credits</h2>
            <p className="muted">Created by Pushkar Khattri. Motion components adapted from Origin Kit, React Bits and 21st.dev. Line figures by Hairline.</p>
          </section>
        </div>
      </div>
    </main>
  )
}
