import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

/** Figures observed in this browser only. Nothing here is seeded or estimated. */
const KEY = 'heimdall_session_stats_v5'
const blank = () => ({ total: 0, BLOCK: 0, PASS: 0, SANITIZE: 0, REVIEW: 0, latencySum: 0, latencyCount: 0, recent: [], attackTypes: {} })
const Ctx = createContext(null)

function load() {
  try {
    const value = JSON.parse(localStorage.getItem(KEY))
    return value && typeof value.total === 'number' && Array.isArray(value.recent) ? { ...blank(), ...value } : blank()
  } catch { return blank() }
}

export function StatsProvider({ children }) {
  const [stats, setStats] = useState(load)

  useEffect(() => {
    try { localStorage.setItem(KEY, JSON.stringify(stats)) } catch { /* private mode */ }
  }, [stats])

  const record = useCallback(({ verdict, latencyMs, attackType }) => {
    setStats((s) => ({
      ...s,
      total: s.total + 1,
      [verdict]: (s[verdict] || 0) + 1,
      latencySum: s.latencySum + (latencyMs || 0),
      latencyCount: s.latencyCount + (latencyMs ? 1 : 0),
      attackTypes: attackType ? { ...s.attackTypes, [attackType]: (s.attackTypes[attackType] || 0) + 1 } : s.attackTypes,
      recent: [...s.recent.slice(-59), { at: Date.now(), verdict, latencyMs: latencyMs || 0 }],
    }))
  }, [])

  const clear = useCallback(() => setStats(blank()), [])
  const value = useMemo(() => ({ stats, record, clear }), [stats, record, clear])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export const useStats = () => useContext(Ctx)
