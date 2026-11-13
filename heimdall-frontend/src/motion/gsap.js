import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { onLenisScroll } from './lenisStore.js'

gsap.registerPlugin(ScrollTrigger)
gsap.config({ nullTargetWarn: false })
onLenisScroll(() => ScrollTrigger.update())

// Content that arrives late (fonts, figures, fetched data, a new tab) moves everything below it.
if (typeof window !== 'undefined') {
  let settled = 0, timer = 0
  const refresh = () => { ScrollTrigger.refresh(); settled = document.body.scrollHeight }
  new ResizeObserver(() => {
    if (Math.abs(document.body.scrollHeight - settled) < 4) return
    clearTimeout(timer)
    timer = setTimeout(refresh, 220)
  }).observe(document.body)
  document.fonts?.ready.then(refresh)
}

export { gsap, ScrollTrigger }
