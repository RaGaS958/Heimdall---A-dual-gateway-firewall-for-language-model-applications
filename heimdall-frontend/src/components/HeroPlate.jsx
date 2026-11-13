import { useEffect, useRef, useState } from 'react'
import { useReducedMotion } from '../motion/reduced.js'
import { PauseCircle, Play } from './icons.js'

const base = import.meta.env.BASE_URL

/** The original Heimdall key art: attack streams meeting the gate. A muted loop that waits for the
 *  viewport, stops when it leaves, never autoplays under reduced motion, and can always be paused. */
export default function HeroPlate() {
  const video = useRef(null)
  const reduced = useReducedMotion()
  const [wanted, setWanted] = useState(true)
  const [playing, setPlaying] = useState(false)

  useEffect(() => {
    const el = video.current
    if (!el) return undefined
    const io = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && wanted && !reduced) el.play().catch(() => {})
      else el.pause()
    }, { threshold: 0.25 })
    io.observe(el)
    return () => io.disconnect()
  }, [wanted, reduced])

  return (
    <div className="hero-plate">
      <div className="hero-plate-in">
        <video ref={video} muted loop playsInline preload="metadata" width="1040" height="832" poster={`${base}video/heimdall-gate.webp`}
          aria-label="Five kinds of prompt attack streaming into the Heimdall gate and stopping there."
          onPlay={() => setPlaying(true)} onPause={() => setPlaying(false)}>
          <source src={`${base}video/heimdall-gate.mp4`} type="video/mp4" />
        </video>
      </div>
      <button className="btn btn-s plate-toggle" onClick={() => { setWanted(!playing); playing ? video.current.pause() : video.current.play().catch(() => {}) }}>
        {playing ? <PauseCircle size={16} aria-hidden="true" /> : <Play size={16} aria-hidden="true" />}{playing ? 'Pause animation' : 'Play animation'}
      </button>
    </div>
  )
}
