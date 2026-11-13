import { useEffect, useMemo, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'motion/react'
import { useReducedMotion } from '../../motion/reduced.js'

/**
 * Adapted from 21st.dev Streaming Data Rows (rmahammad): a real table that animates only what changed.
 * Restyled to project CSS; the row actions and stacked mobile card were dropped because nothing here uses them.
 */
function useAnimatedNumber(value, disabled) {
  const [shown, setShown] = useState(value)
  const from = useRef(value)
  useEffect(() => {
    if (disabled) { setShown(value); from.current = value; return undefined }
    const start = performance.now(), origin = from.current
    let raf = 0
    const tick = (t) => {
      const p = Math.min(1, (t - start) / 320), eased = 1 - (1 - p) ** 3
      const next = origin + (value - origin) * eased
      from.current = next
      setShown(next)
      if (p < 1) raf = requestAnimationFrame(tick)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [value, disabled])
  return shown
}

const Morph = ({ value, format, disabled }) => {
  const n = useAnimatedNumber(value, disabled)
  return format ? format(n) : Math.round(n).toLocaleString()
}

const nextSort = (cur, key) => (!cur || cur.key !== key ? { key, dir: 'asc' } : cur.dir === 'asc' ? { key, dir: 'desc' } : null)

export default function StreamingRows({ rows, columns, getRowId, caption, defaultSort = null, state = 'idle', onRetry, empty, error, loadingRows = 4 }) {
  const reduced = useReducedMotion()
  const [sort, setSort] = useState(defaultSort)
  const [announce, setAnnounce] = useState('')
  const known = useRef(null)

  const sorted = useMemo(() => {
    if (!sort) return rows
    const col = columns.find((c) => c.key === sort.key)
    const factor = sort.dir === 'asc' ? 1 : -1
    return rows.map((row, i) => ({ row, i })).sort((a, b) => {
      const x = col.value(a.row), y = col.value(b.row)
      return x < y ? -factor : x > y ? factor : a.i - b.i
    }).map((e) => e.row)
  }, [rows, columns, sort])

  useEffect(() => {
    const ids = new Set(rows.map(getRowId))
    if (known.current) {
      const added = [...ids].filter((id) => !known.current.has(id)).length
      if (added) { const t = setTimeout(() => setAnnounce(`${added} new ${added === 1 ? 'row' : 'rows'}.`), 1200); known.current = ids; return () => clearTimeout(t) }
    }
    known.current = ids
    return undefined
  }, [rows, getRowId])

  if (state === 'error') return <div className="stream-state" role="alert"><p>{error || 'The live feed is unavailable.'}</p>{onRetry && <button className="btn" onClick={onRetry}>Retry</button>}</div>

  return (
    <div className="stream">
      <div className="visually-hidden" role="status" aria-live="polite">{announce}</div>
      <div className="table-wrap">
        <table className="table" aria-busy={state === 'loading' || undefined}>
          <caption className="visually-hidden">{caption}</caption>
          <thead><tr>{columns.map((c) => {
            const here = sort?.key === c.key ? sort.dir : null
            return (
              <th key={c.key} className={c.numeric ? 'num' : ''} aria-sort={c.sortable ? (here === 'asc' ? 'ascending' : here === 'desc' ? 'descending' : 'none') : undefined}>
                {c.sortable ? <button className="sort-btn" onClick={() => setSort(nextSort(sort, c.key))}>{c.header}<span aria-hidden="true">{here === 'asc' ? ' \u2191' : here === 'desc' ? ' \u2193' : ' \u2195'}</span></button> : c.header}
              </th>
            )
          })}</tr></thead>
          <tbody>
            {state === 'loading' && Array.from({ length: loadingRows }, (_, i) => <tr key={i} aria-hidden="true">{columns.map((c) => <td key={c.key}><span className="skeleton-line" /></td>)}</tr>)}
            {state !== 'loading' && !sorted.length && <tr><td colSpan={columns.length} className="muted stream-empty">{empty || 'Nothing yet.'}</td></tr>}
            {state !== 'loading' && (
              <AnimatePresence initial={false} mode="popLayout">
                {sorted.map((row) => (
                  <motion.tr key={getRowId(row)} layout={reduced ? false : 'position'} initial={reduced ? false : { opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={reduced ? { opacity: 0 } : { opacity: 0, y: 6 }} transition={{ duration: 0.22, ease: [0.2, 0, 0, 1] }}>
                    {columns.map((c) => (
                      <td key={c.key} className={c.numeric ? 'num measured' : ''}>
                        {c.render ? c.render(row) : c.numeric ? <Morph value={c.value(row)} format={c.format} disabled={reduced} /> : c.value(row)}
                      </td>
                    ))}
                  </motion.tr>
                ))}
              </AnimatePresence>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
