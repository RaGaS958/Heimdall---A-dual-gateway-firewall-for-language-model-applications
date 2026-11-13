import { useRef } from 'react'
import { gsap } from '../../motion/gsap.js'
import { useGsap } from '../../motion/useGsap.js'

/** Rebuilt from the published descriptions of Origin Kit and 21st.dev text effects. */
const Words = ({ text, render }) => text.split(' ').map((word, i, all) => (
  <span className="fx-word" key={i}>{render(word, i)}{i < all.length - 1 ? ' ' : ''}</span>
))

/** Origin Kit text-wipe: a heading wiped in from the left the first time it is seen. */
export function TextWipe({ as: Tag = 'h2', children, className = '' }) {
  const ref = useRef(null)
  useGsap((el) => {
    gsap.fromTo(el, { clipPath: 'inset(-10% 100% -20% 0)' }, {
      clipPath: 'inset(-10% -2% -20% 0)', duration: 0.8, ease: 'expo.out', clearProps: 'clipPath',
      scrollTrigger: { trigger: el, start: 'top 88%', once: true },
    })
  }, ref)
  return <Tag ref={ref} className={className}>{children}</Tag>
}

/** Origin Kit rolling-letters: characters roll up into place. */
export function RollingLetters({ as: Tag = 'p', text, className = '' }) {
  const ref = useRef(null)
  useGsap((el) => {
    gsap.from(el.querySelectorAll('.fx-char'), {
      yPercent: 110, duration: 0.7, ease: 'expo.out', stagger: 0.03,
      scrollTrigger: { trigger: el, start: 'top 92%', once: true },
    })
  }, ref)
  return (
    <Tag ref={ref} className={`rolling ${className}`} aria-label={text}>
      <span aria-hidden="true">{[...text].map((c, i) => <span className="fx-clip" key={i}><span className="fx-char">{c === ' ' ? '\u00a0' : c}</span></span>)}</span>
    </Tag>
  )
}

/** 21st.dev Text Reveal (Mask): words slide up from behind a mask. */
export function TextRevealMask({ as: Tag = 'h2', text, className = '' }) {
  const ref = useRef(null)
  useGsap((el) => {
    gsap.from(el.querySelectorAll('.fx-char'), {
      yPercent: 105, duration: 0.65, ease: 'expo.out', stagger: 0.045,
      scrollTrigger: { trigger: el, start: 'top 90%', once: true },
    })
  }, ref)
  return (
    <Tag ref={ref} className={className} aria-label={text}>
      <span aria-hidden="true"><Words text={text} render={(word) => <span className="fx-clip"><span className="fx-char">{word}</span></span>} /></span>
    </Tag>
  )
}
