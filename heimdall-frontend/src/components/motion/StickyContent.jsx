import { useLayoutEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { gsap, ScrollTrigger } from '../../motion/gsap.js'
import { getLenis } from '../../motion/lenisStore.js'
import { prefersReduced } from '../../motion/reduced.js'
import { ArrowRight } from '../icons.js'

/**
 * 21st.dev "Sticky Content Wrapper" by hyperiux (component 26064), ported from the original source.
 * Kept as published: the scrubbed timeline, the step timing (stepGap, contentDelay), the clip-path wipe
 * with the scale flow on the paired visual, the snap points, and the reduced-motion crossfade.
 * Changed for this project: Tailwind classes became CSS, the visual is any node instead of an <img>,
 * links are router links, the Lenis handle is wired to the snap, the fixed "scroll" hint is dropped,
 * and below 1025px the section is a plain stack instead of a pinned one.
 */
export default function StickyContent({
  items, label,
  contentEnterYPercent = 2, contentExitYPercent = -2, contentTransitionDuration = 0.9, contentDelay = 0.35, stepGap = 2,
  enableImageScaleFlow = true, initialImageScale = 1.5, activeImageScale = 1.2, exitImageScale = 1,
}) {
  const sectionRef = useRef(null)
  const contentRefs = useRef([])
  const mediaRefs = useRef([])

  useLayoutEffect(() => {
    if (!sectionRef.current || !items.length) return undefined
    const reducedMotion = prefersReduced()
    const mm = gsap.matchMedia()
    mm.add('(min-width: 1025px)', () => {
      const contents = contentRefs.current
      const visuals = mediaRefs.current
      contents.forEach((content, index) => {
        gsap.set(content, { autoAlpha: index === 0 ? 1 : 0, yPercent: index === 0 ? 0 : contentEnterYPercent, zIndex: items.length - index })
      })
      visuals.forEach((visual, index) => {
        gsap.set(visual, {
          autoAlpha: reducedMotion ? (index === 0 ? 1 : 0) : 1,
          zIndex: items.length - index,
          clipPath: 'inset(0% 0% 0% 0%)',
          scale: reducedMotion ? 1 : enableImageScaleFlow ? (index === 0 ? activeImageScale : initialImageScale) : 1,
          transformOrigin: 'center center',
        })
      })

      const total = Math.max(1, (items.length - 1) * stepGap)
      const snapValues = items.length > 1 ? Array.from({ length: items.length }, (_, i) => i / (items.length - 1)) : [0]
      const release = () => getLenis()?.start()
      const timeline = gsap.timeline({
        scrollTrigger: {
          trigger: sectionRef.current, start: 'top top+=64', end: 'bottom bottom', scrub: 1,
          snap: items.length > 1 && !reducedMotion ? {
            snapTo: snapValues, duration: { min: 0.2, max: 0.5 }, ease: 'power2.inOut', delay: 0, inertia: false,
            onStart: () => getLenis()?.stop(), onComplete: release, onInterrupt: release,
          } : false,
        },
      })

      items.forEach((_, index) => {
        if (index === items.length - 1) return
        const stepStart = index * stepGap
        timeline
          .to(contents[index], { autoAlpha: 0, yPercent: contentExitYPercent, duration: contentTransitionDuration, ease: 'power2.inOut' }, stepStart)
          .fromTo(contents[index + 1], { autoAlpha: 0, yPercent: contentEnterYPercent },
            { autoAlpha: 1, yPercent: 0, duration: contentTransitionDuration, ease: 'power2.inOut' }, stepStart + contentTransitionDuration + contentDelay)
          .to(visuals[index], reducedMotion
            ? { autoAlpha: 0, duration: stepGap, ease: 'none' }
            : { clipPath: 'inset(0% 0% 100% 0%)', scale: enableImageScaleFlow ? exitImageScale : 1, duration: stepGap, ease: 'none' }, stepStart)
        if (reducedMotion) timeline.to(visuals[index + 1], { autoAlpha: 1, duration: stepGap, ease: 'none' }, stepStart)
        else if (enableImageScaleFlow) timeline.to(visuals[index + 1], { scale: activeImageScale, duration: stepGap, ease: 'none' }, stepStart)
      })
      timeline.duration(total)
      ScrollTrigger.refresh()
      return release
    })
    return () => mm.revert()
  }, [items, contentEnterYPercent, contentExitYPercent, contentTransitionDuration, contentDelay, stepGap, enableImageScaleFlow, initialImageScale, activeImageScale, exitImageScale])

  if (!items.length) return null
  return (
    <section ref={sectionRef} className="sc" style={{ '--sc-count': items.length }} aria-label={label}>
      <div className="sc-stage">
        <div className="sc-copy">
          {items.map((item, index) => (
            <article key={item.heading} className="sc-content" ref={(el) => { contentRefs.current[index] = el }}>
              <p className="label">{String(index + 1).padStart(2, '0')} / {String(items.length).padStart(2, '0')}</p>
              <h3>{item.heading}</h3>
              <p className="lead">{item.paragraph}</p>
              {item.list?.length > 0 && <ul>{item.list.map((line) => <li key={line}>{line}</li>)}</ul>}
              {item.link && <Link className="sc-link" to={item.link.href}><span>{item.link.text}</span><ArrowRight size={18} weight="bold" aria-hidden="true" /></Link>}
              <div className="sc-inline-media">{item.media}</div>
            </article>
          ))}
        </div>
        <div className="sc-visuals" aria-hidden="true">
          {items.map((item, index) => (
            <div key={item.heading} className="sc-visual" ref={(el) => { mediaRefs.current[index] = el }}>{item.media}</div>
          ))}
        </div>
      </div>
    </section>
  )
}
