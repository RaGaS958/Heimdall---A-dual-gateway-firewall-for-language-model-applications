import { Component } from 'react'

export default class ErrorBoundary extends Component {
  state = { error: null }

  static getDerivedStateFromError(error) { return { error } }

  componentDidCatch(error, info) { console.error('Heimdall page error', error, info?.componentStack) }

  render() {
    if (!this.state.error) return this.props.children
    const stale = /dynamically imported module|Importing a module/i.test(this.state.error.message || '')
    return (
      <main className="container page">
        <section className="error-panel" role="alert">
          <div>
            <p className="error-title">{stale ? 'A newer version is available' : 'This page failed to draw'}</p>
            <p className="error-why">{stale ? 'The site was updated while this tab was open. Reload to get it.' : this.state.error.message}</p>
          </div>
          <div className="error-actions"><button className="btn btn-primary" onClick={() => window.location.reload()}>Reload</button></div>
        </section>
      </main>
    )
  }
}
