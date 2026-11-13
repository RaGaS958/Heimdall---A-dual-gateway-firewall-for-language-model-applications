import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { gsap, ScrollTrigger } from '../../motion/gsap.js'
import { getLenis, scrollToElement } from '../../motion/lenisStore.js'
import { prefersReduced } from '../../motion/reduced.js'
import { useGsap } from '../../motion/useGsap.js'

/* 21st.dev scroll components. Each export says whether it follows the original source or was rebuilt from the published description. */

/** 21st.dev Scroll Progress (rebuilt from its description): a page-progress line under the top bar. */
export function ScrollProgress() {
  const ref = useRef(null)
  useGsap((el) => {
    gsap.fromTo(el, { scaleX: 0 }, { scaleX: 1, ease: 'none', scrollTrigger: { start: 0, end: 'max', scrub: 0.3 } })
  }, ref)
  return <div ref={ref} className="page-progress" aria-hidden="true" />
}

/** 21st.dev Tracing Beam (rebuilt from its description): a rule that draws down the content as it is read. */
export function TracingBeam({ children, className = '' }) {
  const ref = useRef(null)
  useGsap((el) => {
    gsap.fromTo(el.querySelector('.beam i'), { scaleY: 0 }, {
      scaleY: 1, ease: 'none', scrollTrigger: { trigger: el, start: 'top 70%', end: 'bottom 60%', scrub: 0.4 },
    })
  }, ref)
  return <div ref={ref} className={`beam-wrap ${className}`}><div className="beam" aria-hidden="true"><i /></div><div>{children}</div></div>
}

/** 21st.dev Timeline (rebuilt from its description): sticky labels with a beam that follows the reader. */
export function Timeline({ items }) {
  return (
    <TracingBeam className="timeline">
      <ol>{items.map((item) => <li key={item.label}><h3 className="measured">{item.label}</h3><p>{item.body}</p></li>)}</ol>
    </TracingBeam>
  )
}

const TIERS = { rotateIn: [-60, -80, -100], rotateOut: [50, 65, 80], drift: [2, 6, 10] }

/**
 * 21st.dev "Cards Rotate Slider" by hyperiux (component 27161). Re-implemented from the original source's
 * structure and constants: a tall outer block, a sticky stage with perspective, one scrubbed tween that
 * moves the track, and a nested timeline per card (containerAnimation) that turns it in from depth,
 * lets it settle flat at the centre, and tilts it out. Reduced motion keeps the pan and cuts rotation to 15%.
 * The cards here hold text, not images, so rotationAmount defaults lower than the original's 1.
 */
export function CardsRotateSlider({ label, heading, children, rotationAmount = 0.55, verticalDrift = 1, scrollSmoothing = 0.8, perspective = 1600 }) {
  const outer = useRef(null)
  useLayoutEffect(() => {
    const el = outer.current
    if (!el) return undefined
    const reduced = prefersReduced()
    const ctx = gsap.context(() => {
      const track = el.querySelector('.rot-track')
      const cards = gsap.utils.toArray(el.querySelectorAll('.rot-card'))
      const tier = window.innerWidth < 640 ? 0 : window.innerWidth < 1025 ? 1 : 2
      const k = (reduced ? 0.15 : 1) * rotationAmount
      const travel = () => Math.max(0, track.scrollWidth - window.innerWidth)
      const stage = el.querySelector('.rot-stage')
      const bar = () => window.innerHeight - stage.offsetHeight
      const size = () => { el.style.height = `${travel() + stage.offsetHeight}px` }
      size()
      const pan = gsap.to(track, {
        x: () => -travel(), ease: 'none',
        scrollTrigger: { trigger: el, start: () => `top top+=${bar()}`, end: () => `+=${travel()}`, scrub: scrollSmoothing, invalidateOnRefresh: true, onRefreshInit: size },
      })
      cards.forEach((card, i) => {
        const side = i % 2 ? 1 : -1
        gsap.timeline({ scrollTrigger: { trigger: card, containerAnimation: pan, start: 'left 100%', end: 'right 0%', scrub: true } })
          .fromTo(card,
            { rotateY: TIERS.rotateIn[tier] * k, rotateX: 5 * side * k, opacity: 0.9, yPercent: TIERS.drift[tier] * side * verticalDrift * (reduced ? 0.15 : 1) },
            { rotateY: 0, rotateX: 0, opacity: 1, yPercent: 0, ease: 'none' })
          .to(card, { rotateY: TIERS.rotateOut[tier] * k, ease: 'none' })
      })
    }, el)
    return () => ctx.revert()
  }, [rotationAmount, verticalDrift, scrollSmoothing])
  return (
    <div ref={outer} className="rot" role="group" aria-label={label}>
      <div className="rot-stage" style={{ perspective: `${prefersReduced() ? 4800 : perspective}px` }}>
        {heading && <div className="container rot-head">{heading}</div>}
        <div className="rot-track">{children}</div>
      </div>
    </div>
  )
}

/** 21st.dev Full Screen Scroll FX (rebuilt from its description): a pinned slideshow with a side index. Becomes a plain list on small screens. */
export function FullScreenScroll({ label, slides }) {
  const ref = useRef(null)
  const [active, setActive] = useState(0)
  useGsap((el) => {
    const mm = gsap.matchMedia()
    mm.add('(min-width: 900px)', () => {
      const nodes = gsap.utils.toArray(el.querySelectorAll('.fs-slide'))
      gsap.set(nodes.slice(1), { autoAlpha: 0, yPercent: 12 })
      const tl = gsap.timeline({
        scrollTrigger: {
          trigger: el, start: 'top top+=56', end: () => `+=${(nodes.length - 1) * window.innerHeight * 0.8}`, pin: true, scrub: 0.5,
          snap: { snapTo: 1 / (nodes.length - 1), duration: 0.3, ease: 'power2.out' },
          onUpdate: (self) => setActive(Math.round(self.progress * (nodes.length - 1))),
        },
      })
      nodes.slice(1).forEach((node, i) => {
        tl.to(nodes[i], { autoAlpha: 0, yPercent: -10, ease: 'none', duration: 0.42 }, i + 0.08)
        tl.to(node, { autoAlpha: 1, yPercent: 0, ease: 'none', duration: 0.42 }, i + 0.5)
      })
    })
    return () => mm.revert()
  }, ref)
  const jump = (i) => {
    const st = ScrollTrigger.getAll().find((t) => t.trigger === ref.current)
    if (!st) return
    const top = st.start + (st.end - st.start) * (i / (slides.length - 1))
    if (getLenis()) getLenis().scrollTo(top, { duration: 0.8 })
    else window.scrollTo(0, top)
  }
  return (
    <div ref={ref} className="fs" role="group" aria-label={label}>
      <nav className="fs-index" aria-label={`${label} index`}>
        {slides.map((s, i) => <button key={s.title} className={i === active ? 'is-on' : ''} onClick={() => jump(i)}>{s.title}</button>)}
      </nav>
      <ol className="fs-slides">
        {slides.map((s) => <li className="fs-slide" key={s.title}><h3>{s.title}</h3><p className="lead">{s.body}</p><p className="measured muted">Handled by {s.meta}</p></li>)}
      </ol>
    </div>
  )
}

/** Adapted from Origin Kit scroll-progress-outline, with real links so it works from the keyboard. */
export function ScrollOutline({ title = 'On this page', items }) {
  const ref = useRef(null)
  const [active, setActive] = useState(0)
  useEffect(() => {
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => { if (e.isIntersecting) setActive(items.findIndex((x) => x.id === e.target.id)) })
    }, { rootMargin: '-45% 0px -50% 0px' })
    items.forEach((item) => { const t = document.getElementById(item.id); if (t) io.observe(t) })
    return () => io.disconnect()
  }, [items])
  return (
    <nav ref={ref} className="outline" aria-label={title}>
      <p className="muted">{title}</p>
      <ol style={{ '--active': active }}>
        <i className="outline-arrow" aria-hidden="true" />
        {items.map((item, i) => (
          <li key={item.id} className={i === active ? 'is-on' : i < active ? 'is-past' : ''}>
            <a href={`#${item.id}`} aria-current={i === active ? 'true' : undefined} onClick={(e) => { e.preventDefault(); scrollToElement(document.getElementById(item.id)) }}>{item.label}</a>
          </li>
        ))}
      </ol>
    </nav>
  )
}
