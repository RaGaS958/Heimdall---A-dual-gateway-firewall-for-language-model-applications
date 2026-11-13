# Third-party components

| Source | Component | File | Status |
|---|---|---|---|
| **21st.dev** (hyperiux) | Sticky Content Wrapper, 26064 | `src/components/motion/StickyContent.jsx` | **Ported from the original source.** Timeline, timings, clip-path wipe, scale flow, snap points and reduced-motion crossfade are as published. Tailwind classes became CSS, the visual is any node, the fixed scroll hint is dropped, and below 1025px it is a plain stack |
| **21st.dev** (hyperiux) | Cards Rotate Slider, 27161 | `motion/ScrollFx.jsx` | **Re-implemented from the original source's structure and constants** (sticky stage, scrubbed track, per-card nested timeline, breakpoint tiers, 15% reduced-motion factor). The verbatim file was not kept, so treat it as a close rebuild |
| **21st.dev** | Hero Scrub (jean.duthil13), Streaming Data Rows (rmahammad) | `motion/HeroScrub.jsx`, `motion/StreamingRows.jsx` | Adapted from the original source. Hero Scrub is not mounted; it is ready for new footage |
| **21st.dev** | Tracing Beam, Timeline, Full Screen Scroll FX, Scroll Progress, Text Reveal (Mask), Animated Tabs, Animated Bar Chart, Analytics Bento, Typing Text | `motion/ScrollFx.jsx`, `TextFx.jsx`, `Controls.jsx`, `DataViz.jsx` | **Rebuilt** from the published description. Not 21st code |
| **React Bits** | Scroll Reveal, Split Flap Text, Count Up, Scroll Velocity, Animated Content, Animated List, Stepper, Counter, Magnet, Glare Hover, Gradual Blur, Decrypted Text | `src/components/reactbits` | Original source. Corners set to square, default theme set to light, sample data and icon imports removed |
| **MotionSites** | "ConSentinel" hero (nival-cyberspace) | Home proof row: two large numerals split by a diagonal rule | Layout pattern only, written from the prompt. No MotionSites code or media |
| **MotionSites** | "VeilGuard" call to action (veilguard-cta) | `src/components/FlowCard.jsx`: inputs, connectors, hub, verdicts | Layout pattern only, written from the prompt |
| **Origin Kit** | text-reveal-wall, scroll-text-highlight, scroll-progress-outline | `motion/TextWall.jsx`, `ScrollHighlight.jsx`, `ScrollFx.jsx` | Adapted from the original source |
| **Origin Kit** | text-wipe, focus-reveal, rolling-letters, hairline-loader, scan-grid-button, encrypt-button | `motion/TextFx.jsx`, `FocusReveal.jsx`, `Buttons.jsx` | **Rebuilt** from the published description. Not Origin Kit code |
| **Hairline** | Isometric figures | `src/components/Figure.jsx` | npm package `@lucasmarkes/hairline`, light theme |
| **Phosphor Icons** | Icons | `src/components/icons.js` | npm package `@phosphor-icons/react`, MIT |
| **Fontsource** | Barlow, Barlow Condensed, JetBrains Mono | `src/main.jsx` | npm packages, SIL Open Font License |

Removed in the white, red and blue redesign because they did not belong to one visual language: React Bits Scanner, Radar, Letter Glitch, Faulty Terminal, Spotlight Card and Pixel Transition, and Scroll Stack (it hid the Known limits text behind stacked cards); Origin Kit glyph-ripple; and the rebuilt ascii-radar, character-waves and depth-code-stream backgrounds.

Rebuilt items exist because of daily download limits on the free plans (21st.dev: two retrievals a day; Origin Kit: three; MotionSites: three prompts in total). Each can be replaced with the original later.

React Bits is licensed as MIT with the Commons Clause (`src/components/reactbits/LICENSE.react-bits.md`). The clause bars selling the components themselves or a product whose value comes substantially from them, so read it before commercial distribution. Check the terms of 21st.dev authors, MotionSites and Origin Kit the same way.

## Hero video

`public/video/heimdall-gate.mp4` is the project's own original hero video, changed in three ways: cropped to the left 1336 of 1920 pixels (the removed part showed third-party provider logos and a panel of invented figures), a garbled subtitle under the wordmark removed with ffmpeg `delogo`, and re-encoded from 8.2 MB to 1.1 MB. The command is in `public/video/README.md`.
