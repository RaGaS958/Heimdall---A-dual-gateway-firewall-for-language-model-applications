import { Suspense, lazy, useEffect, useState } from 'react'
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation } from 'react-router-dom'
import ErrorBoundary from './components/ErrorBoundary.jsx'
import { LogoLockup } from './components/Logo.jsx'
import { PageHead } from './components/ui.jsx'
import { HairlineLoader } from './components/motion/Buttons.jsx'
import { ArrowRight, List, X } from './components/icons.js'
import SmoothScroll from './motion/SmoothScroll.jsx'
import { HealthProvider, useHealth } from './context/HealthContext.jsx'
import { StatsProvider } from './context/StatsContext.jsx'

const Home = lazy(() => import('./pages/Home.jsx'))
const Chat = lazy(() => import('./pages/Chat.jsx'))
const Simulation = lazy(() => import('./pages/Simulation.jsx'))
const Analytics = lazy(() => import('./pages/Analytics.jsx'))
const ImmuneSystem = lazy(() => import('./pages/ImmuneSystem.jsx'))
const Research = lazy(() => import('./pages/Research.jsx'))
const About = lazy(() => import('./pages/About.jsx'))
const ReviewQueue = lazy(() => import('./pages/ReviewQueue.jsx'))
const Policy = lazy(() => import('./pages/Policy.jsx'))
const DebugConsole = lazy(() => import('./pages/DebugConsole.jsx'))

const PRIMARY = [['Console', '/chat'], ['Attack Lab', '/simulation'], ['Analytics', '/analytics'], ['Immune', '/immune'], ['Research', '/research'], ['About', '/about']]
const OPERATE = [['Review queue', '/review'], ['Policies', '/policies'], ['Debug', '/debug']]

function HealthStatus() {
  const { health, error, loading } = useHealth()
  let word = 'Checking', tone = 'muted', detail = 'Contacting the middleware.'
  if (!loading || health) {
    if (error && !health) { word = 'Offline'; tone = 'bad'; detail = 'The middleware did not answer. Scans and chat are unavailable.' }
    else if (health) {
      const backend = health.components?.multi_llm_backend === 'ok'
      const arbiter = health.components?.agentic === 'ok'
      if (backend && arbiter) { word = 'Online'; tone = 'ok'; detail = 'Both gateways, the arbiter and the model backend are up.' }
      else if (!backend) { word = 'No models'; tone = 'accent'; detail = 'Firewall is up, but the multi-LLM backend is unreachable. Scans work; chat will not.' }
      else { word = 'No arbiter'; tone = 'accent'; detail = 'No Groq or Gemini key: strong signals fail closed and are blocked.' }
    }
  }
  return <span className={`chip chip-${tone}`} title={detail} aria-live="polite">{word}</span>
}

function Shell({ children }) {
  const [open, setOpen] = useState(false)
  const location = useLocation()
  useEffect(() => { setOpen(false); window.scrollTo(0, 0) }, [location.pathname])
  const link = ([label, to]) => <NavLink key={to} to={to} className="nav-link">{label}</NavLink>
  return (
    <>
      <SmoothScroll />
      <a className="skip" href="#main">Skip to content</a>
      <header className="topbar">
        <div className="topbar-in">
          <Link to="/" aria-label="Heimdall home"><LogoLockup /></Link>
          <nav id="primary-nav" className={`nav ${open ? 'is-open' : ''}`} aria-label="Primary">
            {PRIMARY.map(link)}
            <span className="nav-sep" />
            {OPERATE.map(link)}
          </nav>
          <div className="topbar-side">
            <HealthStatus />
            <Link className="btn btn-primary btn-s topbar-cta" to="/chat">Open console <ArrowRight size={14} weight="bold" aria-hidden="true" /></Link>
            <button className="btn btn-s btn-menu" aria-expanded={open} aria-controls="primary-nav" onClick={() => setOpen((v) => !v)}>
              {open ? <X size={16} weight="bold" aria-hidden="true" /> : <List size={16} weight="bold" aria-hidden="true" />}Menu
            </button>
          </div>
        </div>
      </header>
      <div id="main">{children}</div>
    </>
  )
}

function NotFound() {
  return (
    <main className="container page">
      <PageHead title="No such page" figure="Query" figureLabel="A query with no match">The address does not match a Heimdall page.</PageHead>
      <p><Link className="btn btn-primary" to="/">Go to the start page</Link></p>
    </main>
  )
}

export default function App() {
  return (
    <HealthProvider>
      <StatsProvider>
        <BrowserRouter>
          <Shell>
            <ErrorBoundary>
              <Suspense fallback={<main className="container page"><HairlineLoader /></main>}>
                <Routes>
                  <Route path="/" element={<Home />} />
                  <Route path="/chat" element={<Chat />} />
                  <Route path="/simulation" element={<Simulation />} />
                  <Route path="/analytics" element={<Analytics />} />
                  <Route path="/immune" element={<ImmuneSystem />} />
                  <Route path="/research" element={<Research />} />
                  <Route path="/about" element={<About />} />
                  <Route path="/review" element={<ReviewQueue />} />
                  <Route path="/policies" element={<Policy />} />
                  <Route path="/debug" element={<DebugConsole />} />
                  <Route path="*" element={<NotFound />} />
                </Routes>
              </Suspense>
            </ErrorBoundary>
          </Shell>
        </BrowserRouter>
      </StatsProvider>
    </HealthProvider>
  )
}
