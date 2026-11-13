import { createContext, useContext, useMemo } from 'react'
import { useFetch } from '../hooks/useFetch.js'
import { api } from '../lib/api.js'

const Ctx = createContext({ health: null, error: null, loading: true, reload: () => {} })

export function HealthProvider({ children }) {
  const { data, error, loading, reload } = useFetch(() => api('/health', { timeout: 70000 }), [], { interval: 30000 })
  const value = useMemo(() => ({ health: data, error, loading, reload }), [data, error, loading, reload])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export const useHealth = () => useContext(Ctx)
