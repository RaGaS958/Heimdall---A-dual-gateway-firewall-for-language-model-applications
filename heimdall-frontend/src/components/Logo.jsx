/** The original Heimdall mark: a diamond gate with one point at its centre.
 *  One source for the nav, the favicon set and the README lockups (assets/logo). */
export function LogoMark({ size = 24, className = '' }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className={className} aria-hidden="true">
      <path d="M12 2.6 21.4 12 12 21.4 2.6 12Z" stroke="currentColor" strokeWidth="2.4" strokeLinejoin="miter" />
      <path d="M12 8.4 15.6 12 12 15.6 8.4 12Z" fill="var(--color-blue, #2563EB)" />
    </svg>
  )
}

export function LogoLockup({ size = 26 }) {
  return (
    <span className="logo">
      <LogoMark size={size} />
      <span className="logo-word">Heimdall</span>
    </span>
  )
}
