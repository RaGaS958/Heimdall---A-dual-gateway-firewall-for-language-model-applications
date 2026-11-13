import { Suspense, lazy } from 'react'

const names = ['Query', 'Riffle', 'Branches', 'Loupe', 'Terminal', 'Vault', 'Router', 'Sieve', 'Patch', 'Phosphor']
const figures = Object.fromEntries(names.map((name) => [
  name,
  lazy(() => import('./hairlineFigures.js').then((m) => ({ default: m[name] }))),
]))

/** Hairline illustrations are explanatory; they load after the page and never block it. */
export function Figure({ name, label, intensity = 0.6, play = false, className = '' }) {
  const Component = figures[name]
  return (
    <div className={`hairline ${className}`}>
      <Suspense fallback={null}>
        <Component theme="light" intensity={intensity} label={label} play={play} />
      </Suspense>
    </div>
  )
}
