import { useEffect, useRef, useState } from 'react'
import { gsap } from '../../motion/gsap.js'
import { useReducedMotion } from '../../motion/reduced.js'

const MANIFEST = '/video/hero/manifest.json'

/**
 * Adapted from 21st.dev Hero Scrub (jean.duthil13), restyled to the project's square, flat system.
 * Frames come from scripts/extract-hero-frames.sh. Until footage exists the `fallback` plays in the card.
 */
export default function HeroScrub({ titleTop, titleBottom, fallback, label }) {
  const section = useRef(null), card = useRef(null), canvas = useRef(null), top = useRef(null), bottom = useRef(null)
  const images = useRef([]), drawn = useRef(-1)
  const reduced = useReducedMotion()
  const [manifest, setManifest] = useState(null)
  const [ready, setReady] = useState(false)
  const aspect = manifest?.aspect || 16 / 9

  useEffect(() => {
    let live = true
    fetch(MANIFEST).then((r) => {
      const json = r.ok && (r.headers.get('content-type') || '').includes('json')
      return json ? r.json() : null
    }).then((m) => { if (live && m?.frameCount) setManifest(m) }).catch(() => {})
    return () => { live = false }
  }, [])

  // Frames are fetched once the section enters view, so they never slow the first screen.
  useEffect(() => {
    if (!manifest || !section.current) return undefined
    const url = (i) => `/video/hero/${String(i + 1).padStart(4, '0')}.webp`
    const load = (i) => {
      const img = new Image()
      img.decoding = 'async'
      if (i === 0) img.onload = () => {
        const c = canvas.current
        if (c) { c.width = img.naturalWidth; c.height = img.naturalHeight; c.getContext('2d').drawImage(img, 0, 0); drawn.current = 0 }
        setReady(true)
      }
      img.src = url(i)
      images.current[i] = img
    }
    let timer = 0
    const io = new IntersectionObserver(([e]) => {
      if (!e.isIntersecting) return
      io.disconnect()
      load(0)
      if (reduced || navigator.connection?.saveData) return
      let i = 1
      const batch = () => {
        for (const end = Math.min(manifest.frameCount, i + 12); i < end; i++) load(i)
        if (i < manifest.frameCount) timer = setTimeout(batch, 90)
      }
      batch()
    })
    io.observe(section.current)
    return () => { io.disconnect(); clearTimeout(timer) }
  }, [manifest, reduced])

  useEffect(() => {
    if (reduced || !section.current) return undefined
    const count = manifest?.frameCount || 0
    const isLoaded = (i) => images.current[i]?.complete && images.current[i].naturalWidth > 0
    const draw = (index) => {
      let use = index
      if (!isLoaded(use)) {
        use = -1
        for (let d = 1; d < count && use < 0; d++) {
          if (isLoaded(index - d)) use = index - d
          else if (isLoaded(index + d)) use = index + d
        }
      }
      if (use < 0 || use === drawn.current || !canvas.current) return
      canvas.current.getContext('2d').drawImage(images.current[use], 0, 0, canvas.current.width, canvas.current.height)
      drawn.current = use
    }
    const ctx = gsap.context(() => {
      const startScale = () => (window.innerWidth < 768 ? 0.82 : 0.6)
      const fill = () => {
        const vw = window.innerWidth, vh = window.innerHeight
        const w = Math.min(vw * 0.96, vh * 0.72 * aspect), h = Math.min(vh * 0.72, (vw * 0.96) / aspect)
        return Math.max(vw / w, vh / h) * 1.04
      }
      gsap.set(card.current, { scale: startScale(), transformOrigin: '50% 50%' })
      const master = gsap.timeline({
        scrollTrigger: {
          trigger: section.current, start: 'top top', end: 'bottom bottom', scrub: 0.4, invalidateOnRefresh: true,
          onUpdate: (self) => count && draw(Math.min(count - 1, Math.floor(gsap.utils.clamp(0, 1, (self.progress - 0.15) / 0.63) * count))),
        },
      })
      const out = (el, x) => master.to(el, { x: () => (window.innerWidth < 768 ? `${x * 70}vw` : `${x * 60}vw`), ease: 'power2.inOut', duration: 0.15 }, 0)
      master.to(card.current, { scale: 1, ease: 'power2.out', duration: 0.15 }, 0)
      out(top.current, -1); out(bottom.current, 1)
      master.to(card.current, { scale: fill, ease: 'power2.in', duration: 0.63 }, 0.15)
      master.to([top.current, bottom.current], { opacity: 0, ease: 'power1.in', duration: 0.22 }, 0.15)
      master.to(card.current, { scale: startScale, ease: 'power3.inOut', duration: 0.22 }, 0.78)
      master.to([top.current, bottom.current], { x: 0, opacity: 1, ease: 'power2.inOut', duration: 0.22 }, 0.78)
    }, section)
    return () => ctx.revert()
  }, [reduced, aspect, manifest, ready])

  return (
    <section ref={section} className={`scrub ${reduced ? 'is-static' : ''}`} aria-label={label}>
      <div className="scrub-stage">
        <p ref={top} className="scrub-title" aria-hidden="true">{titleTop}</p>
        <div ref={card} className="scrub-card" style={{ '--aspect': aspect }}>
          {manifest && <canvas ref={canvas} aria-hidden="true" />}
          {!ready && fallback}
        </div>
        <p ref={bottom} className="scrub-title" aria-hidden="true">{titleBottom}</p>
      </div>
    </section>
  )
}
