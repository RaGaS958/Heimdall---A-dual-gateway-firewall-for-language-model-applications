import { useRef } from 'react'
import { useGsap } from '../../motion/useGsap.js'
import { gsap } from '../../motion/gsap.js'

/** Adapted from Origin Kit scroll-text-highlight. The dim state still passes contrast at this size, so nothing is unreadable mid-scroll. */
export default function ScrollHighlight({ text, className = '' }) {
  const ref = useRef(null)
  useGsap((el) => {
    gsap.fromTo(el.querySelectorAll('span'), { opacity: 0.62 }, {
      opacity: 1, stagger: 0.1, ease: 'none',
      scrollTrigger: { trigger: el, start: 'top 75%', end: 'bottom 45%', scrub: 0.4 },
    })
  }, ref, [text])
  return <p ref={ref} className={`scroll-highlight ${className}`}>{text.split(' ').map((w, i) => <span key={i}>{w} </span>)}</p>
}
