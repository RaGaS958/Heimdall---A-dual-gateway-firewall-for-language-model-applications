import { useEffect, useRef, useState } from 'react'
import { motion } from 'motion/react'
import { useReducedMotion } from '../../motion/reduced.js'

/* Rebuilt from the published descriptions of the components named on each export. */

/** 21st.dev Typing Text: real output typed once. A click completes it. */
export function TypingText({ text, className = '' }) {
  const reduced = useReducedMotion()
  const [count, setCount] = useState(reduced ? text.length : 0)
  useEffect(() => {
    if (reduced) { setCount(text.length); return undefined }
    setCount(0)
    const step = Math.max(1, Math.ceil(text.length / 90))
    const timer = setInterval(() => setCount((c) => { if (c >= text.length) clearInterval(timer); return Math.min(text.length, c + step) }), 16)
    return () => clearInterval(timer)
  }, [text, reduced])
  return <pre className={`code typing ${className}`} aria-label={text} onClick={() => setCount(text.length)}><span aria-hidden="true">{text.slice(0, count)}{count < text.length && <i className="caret" />}</span></pre>
}

/** 21st.dev Animated Tabs: a marker slides between tabs. Arrow keys move between them. */
export function AnimatedTabs({ tabs, value, onChange, label }) {
  const reduced = useReducedMotion()
  const refs = useRef({})
  const onKey = (e, index) => {
    const delta = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0
    if (!delta) return
    e.preventDefault()
    const next = tabs[(index + delta + tabs.length) % tabs.length][0]
    onChange(next); refs.current[next]?.focus()
  }
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map(([id, text], i) => (
        <button key={id} ref={(el) => { refs.current[id] = el }} role="tab" aria-selected={value === id} tabIndex={value === id ? 0 : -1} className={value === id ? 'is-on' : ''} onClick={() => onChange(id)} onKeyDown={(e) => onKey(e, i)}>
          {text}
          {value === id && <motion.span layoutId={label} className="tab-marker" transition={reduced ? { duration: 0 } : { type: 'spring', stiffness: 420, damping: 36 }} />}
        </button>
      ))}
    </div>
  )
}
