import { useEffect, useMemo, useRef, useState } from 'react'
import { gsap } from '../../motion/gsap.js'
import { useReducedMotion } from '../../motion/reduced.js'

const CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
const pick = () => CHARS[Math.floor(Math.random() * CHARS.length)]

/** Adapted from Origin Kit text-reveal-wall: scramble sweeps each line, then settles to the real words. */
export default function TextWall({ words, fontSize = 15, stagger = 0.06 }) {
  const box = useRef(null)
  const lines = useRef([])
  const reduced = useReducedMotion()
  const [grid, setGrid] = useState({ cols: 0, rows: 0 })

  useEffect(() => {
    const el = box.current
    const measure = () => {
      const r = el.getBoundingClientRect()
      setGrid({ cols: Math.floor(r.width / (fontSize * 0.62)), rows: Math.floor(r.height / (fontSize * 1.25)) })
    }
    measure()
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [fontSize])

  const layout = useMemo(() => {
    if (!grid.rows) return []
    return Array.from({ length: grid.rows }, (_, row) => {
      const index = Math.floor((row / grid.rows) * words.length)
      const word = row % 2 === 1 ? words[index % words.length] : null
      const start = word ? Math.floor(Math.random() * Math.max(1, grid.cols - word.length)) : -1
      return { word, start }
    })
  }, [grid, words])

  useEffect(() => {
    if (!layout.length) return undefined
    const render = (i, reveal, settle) => {
      const { word, start } = layout[i]
      const shown = Math.floor(reveal * grid.cols), settled = Math.floor(settle * grid.cols)
      let plain = ''
      let html = ''
      for (let c = 0; c < grid.cols; c++) {
        if (word && c >= start && c < start + word.length && c < shown) {
          if (plain) { html += plain; plain = '' }
          html += `<b>${word[c - start]}</b>`
        } else plain += c < shown && c >= settled ? pick() : ' '
      }
      if (lines.current[i]) lines.current[i].innerHTML = html + plain
    }
    if (reduced) { layout.forEach((_, i) => render(i, 1, 1)); return undefined }
    const states = layout.map(() => ({ reveal: 0, settle: 0 }))
    const tl = gsap.timeline({ repeat: -1, yoyo: true, repeatDelay: 2.2, paused: true })
    states.forEach((state, i) => {
      const draw = () => render(i, state.reveal, state.settle)
      tl.to(state, { reveal: 1, duration: 0.9, ease: 'power2.inOut', onUpdate: draw }, i * stagger)
      tl.to(state, { settle: 1, duration: 0.9, ease: 'power2.inOut', onUpdate: draw }, i * stagger + 0.45)
    })
    const io = new IntersectionObserver(([e]) => (e.isIntersecting ? tl.play() : tl.pause()))
    io.observe(box.current)
    return () => { io.disconnect(); tl.kill() }
  }, [layout, grid, reduced, stagger])

  return (
    <div ref={box} className="text-wall" style={{ fontSize }} aria-hidden="true">
      {layout.map((_, i) => <div key={i} ref={(el) => { lines.current[i] = el }} />)}
    </div>
  )
}
