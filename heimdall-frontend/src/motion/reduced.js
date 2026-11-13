import { useEffect, useState } from 'react'

const query = '(prefers-reduced-motion: reduce)'
export const prefersReduced = () => typeof window !== 'undefined' && window.matchMedia(query).matches

/** Follows the system setting live, so a change applies without a reload. */
export function useReducedMotion() {
  const [reduced, setReduced] = useState(prefersReduced)
  useEffect(() => {
    const list = window.matchMedia(query)
    const update = () => setReduced(list.matches)
    list.addEventListener('change', update)
    return () => list.removeEventListener('change', update)
  }, [])
  return reduced
}
