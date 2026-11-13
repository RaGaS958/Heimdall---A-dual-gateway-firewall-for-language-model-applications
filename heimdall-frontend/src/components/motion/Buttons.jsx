import { useEffect, useRef, useState } from 'react'
import { useReducedMotion } from '../../motion/reduced.js'

/* Rebuilt from the published descriptions of the Origin Kit components named on each export. */

/** Origin Kit hairline-loader: one rule drawn across, used while a page loads. */
export const HairlineLoader = ({ label = 'Loading page' }) => <div className="hairline-loader" role="status" aria-label={label}><i /></div>

/** Origin Kit scan-grid-button: corner brackets that snap to the edges. */
export function ScanGridButton({ className = '', children, ...props }) {
  return <button className={`btn scan-btn ${className}`} {...props}><i /><i /><i /><i /><span>{children}</span></button>
}

const CIPHER = '!<>-_\\/[]{}=+*^?#'

/** Origin Kit encrypt-button: the label scrambles, then decrypts left to right. */
export function EncryptButton({ className = '', children, ...props }) {
  const text = String(children)
  const [shown, setShown] = useState(text)
  const timer = useRef(0)
  const reduced = useReducedMotion()
  useEffect(() => { setShown(text); return () => clearInterval(timer.current) }, [text])
  const run = () => {
    if (reduced) return
    clearInterval(timer.current)
    let frame = 0
    const total = 14
    timer.current = setInterval(() => {
      frame += 1
      const solved = Math.floor((frame / total) * text.length)
      setShown([...text].map((c, i) => (i < solved || c === ' ' ? c : CIPHER[(i + frame * 3) % CIPHER.length])).join(''))
      if (frame >= total) { clearInterval(timer.current); setShown(text) }
    }, 28)
  }
  return <button className={`btn encrypt-btn ${className}`} onMouseEnter={run} onFocus={run} aria-label={text} {...props}><span aria-hidden="true" className="measured">{shown}</span></button>
}
