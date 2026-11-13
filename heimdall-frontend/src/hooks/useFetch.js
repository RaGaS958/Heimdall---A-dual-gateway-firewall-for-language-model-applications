import { useCallback, useEffect, useRef, useState } from 'react'

/** Load data with the four states every region must show: loading, error, empty, full. */
export function useFetch(loader, deps = [], { enabled = true, interval = 0 } = {}) {
  const [state, setState] = useState({ loading: enabled, error: null, data: null })
  const latest = useRef(loader)
  latest.current = loader
  const run = useRef(0)

  const reload = useCallback(async ({ quiet = false } = {}) => {
    const ticket = ++run.current
    if (!quiet) setState((s) => ({ ...s, loading: true, error: null }))
    try {
      const data = await latest.current()
      if (ticket === run.current) setState({ loading: false, error: null, data })
    } catch (error) {
      if (ticket === run.current) setState((s) => ({ loading: false, error, data: quiet ? s.data : null }))
    }
  }, [])

  useEffect(() => {
    if (!enabled) { setState({ loading: false, error: null, data: null }); return undefined }
    reload()
    if (!interval) return undefined
    const id = setInterval(() => { if (!document.hidden) reload({ quiet: true }) }, interval)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, interval, reload, ...deps])

  return { ...state, reload }
}
