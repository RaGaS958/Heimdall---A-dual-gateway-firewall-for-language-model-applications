export const LAYERS = [
  { id: 'L0', name: 'Attack cache', gateway: 'G1', job: 'Exact and near-duplicate lookup of known attacks' },
  { id: 'L2', name: 'Canonicalizer', gateway: 'G1', job: 'Removes hidden characters, undoes encodings' },
  { id: 'L1', name: 'Pattern engine', gateway: 'G1', job: 'Rules run over every decoded view' },
  { id: 'L3', name: 'ML classifier', gateway: 'G1', job: 'Learned lexical and semantic similarity' },
  { id: 'L4', name: 'Intent engine', gateway: 'G1', job: 'Authority, urgency and evasion signals' },
  { id: 'L5', name: 'Arbiter', gateway: 'G1', job: 'A model rules on ambiguous evidence' },
  { id: 'O1', name: 'Output cache', gateway: 'G2', job: 'Known-bad responses' },
  { id: 'O2', name: 'Leakage detector', gateway: 'G2', job: 'Canaries, prompt overlap, secrets, personal data' },
  { id: 'O3', name: 'Behaviour check', gateway: 'G2', job: 'Persona shift and override compliance' },
  { id: 'O4', name: 'Exfiltration guard', gateway: 'G2', job: 'Auto-loading links, shell pipes, worms' },
  { id: 'O5', name: 'Arbiter', gateway: 'G2', job: 'A model rules on ambiguous findings' },
]

/** The one definition of the severity scale used everywhere in the product. */
export const SEVERITY_BANDS = [
  { from: 1, to: 6, name: 'Soft', tone: 'cool', effect: 'Arbiter reviews it. If unreachable, forwarded fenced as data.' },
  { from: 7, to: 8, name: 'Strong', tone: 'accent', effect: 'Arbiter decides. If unreachable, blocked.' },
  { from: 9, to: 10, name: 'Critical', tone: 'bad', effect: 'Blocked when corroborated. The arbiter cannot clear it.' },
]

export function bandFor(severity) {
  return SEVERITY_BANDS.find((b) => severity >= b.from && severity <= b.to) || null
}

export const fmtMs = (v) => (v == null ? 'n/a' : v >= 1000 ? `${(v / 1000).toFixed(2)} s` : v >= 10 ? `${Math.round(v)} ms` : `${Number(v).toFixed(1)} ms`)
export const fmtPct = (v, digits = 1) => (v == null || Number.isNaN(v) ? 'n/a' : `${(v * 100).toFixed(digits)}%`)
