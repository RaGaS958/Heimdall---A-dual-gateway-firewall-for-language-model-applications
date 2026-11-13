import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource/barlow-condensed/latin-800.css'
import '@fontsource/barlow/latin-400.css'
import '@fontsource/barlow/latin-600.css'
import '@fontsource/jetbrains-mono/latin-400.css'
import './styles/app.css'
import './styles/motion.css'
import './styles/home.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
