import { useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { getLenis, notifyScroll, setLenis } from './lenisStore.js'
import { prefersReduced } from './reduced.js'

// Panels that scroll on their own keep native scrolling.
const NESTED = '.log, .console-trace, .max-h, .nav.is-open, textarea, select'

export default function SmoothScroll() {
  const { pathname } = useLocation()

  useEffect(() => {
    if (prefersReduced()) return undefined
    let cancelled = false, frame = 0, lenis = null
    const start = async () => {
      const { default: Lenis } = await import('lenis')
      if (cancelled) return
      lenis = new Lenis({ lerp: 0.14, smoothWheel: true, prevent: (node) => !!node.closest?.(NESTED) })
      lenis.on('scroll', notifyScroll)
      setLenis(lenis)
      const raf = (time) => { lenis.raf(time); frame = requestAnimationFrame(raf) }
      frame = requestAnimationFrame(raf)
    }
    const idle = window.requestIdleCallback || ((fn) => setTimeout(fn, 200))
    idle(start)
    return () => { cancelled = true; cancelAnimationFrame(frame); lenis?.destroy(); setLenis(null) }
  }, [])

  useEffect(() => { getLenis()?.scrollTo(0, { immediate: true, force: true }) }, [pathname])
  return null
}
