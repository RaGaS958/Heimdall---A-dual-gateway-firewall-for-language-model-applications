import { useLayoutEffect } from 'react'
import { gsap } from './gsap.js'
import { useReducedMotion } from './reduced.js'

/** Runs a GSAP setup scoped to a ref, reverts it on cleanup, and skips it under reduced motion. */
export function useGsap(setup, ref, deps = []) {
  const reduced = useReducedMotion()
  useLayoutEffect(() => {
    if (reduced || !ref.current) return undefined
    const ctx = gsap.context(() => setup(ref.current), ref)
    return () => ctx.revert()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reduced, ...deps])
  return reduced
}
