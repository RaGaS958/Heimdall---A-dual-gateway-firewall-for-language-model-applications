/** Shared handle to the one Lenis instance, kept free of GSAP so the first load stays small. */
let instance = null
const listeners = new Set()

export const getLenis = () => instance
export function setLenis(next) { instance = next }
export function notifyScroll() { listeners.forEach((fn) => fn()) }
export function onLenisScroll(fn) { listeners.add(fn); return () => listeners.delete(fn) }

export function scrollToElement(target, offset = -72) {
  if (instance) instance.scrollTo(target, { offset, duration: 0.9 })
  else target.scrollIntoView()
}
