# Heimdall design system

The original Heimdall identity: a white page, navy ink, **blue for the guard**, **red for the threat**. Tokens are in `src/styles/tokens.css`. Change a value there, never in a component.

## Colour

| Role | Token | Value | Used for |
|---|---|---|---|
| Page | `--color-paper` | `#FFFFFF` | Page and panel surfaces |
| Tint | `--color-paper-2`, `--color-paper-3` | `#F6F8FB`, `#EDF1F7` | Bands, table hover, chart tracks |
| Ink | `--color-ink` / `--color-navy` | `#0A0F1E` | Text, primary buttons, rules that carry weight |
| Secondary text | `--color-muted` | `#475569` | Supporting copy, labels (7.6:1 on white) |
| Rules | `--color-rule`, `--color-rule-2` | `#E2E8F0`, `#CBD5E1` | Hairlines between and around panels |
| Control edge | `--color-field` | `#64748B` | Input and chip-button borders (4.7:1, so a field is visible without its fill) |
| Guard | `--color-blue`, `--color-blue-deep` | `#2563EB`, `#1D4ED8` | Active states, links, focus, the logo point, anything Heimdall does |
| Threat | `--color-red`, `--color-red-deep` | `#DC2626`, `#B91C1C` | Blocked verdicts, attack text, the one emphasised phrase in a headline |

Red and blue carry meaning, so neither is decoration. A red element is an attack or a block. A blue element is the firewall or something you can act on.

Two more colours exist only as **data states**: green `#047857` for "passed" and amber `#B45309` for "held for review". They appear in status chips, the trace and chart series, and nowhere in the page chrome. The original design used the same two.

Every text colour passes 4.5:1 on white and on its own soft tint. Rerun a contrast audit when a token changes.

## Type

| Role | Family | Use |
|---|---|---|
| Display | Barlow Condensed 800, uppercase | `h1`, `h2`, panel titles, big numerals |
| Body | Barlow 400 and 600 | Everything a person reads; `h3` |
| Data | JetBrains Mono 400 | Measured values, layer ids, evidence, small uppercase labels (`.label`) |

Three weights in total (400, 600, 800). All three families are self-hosted through `@fontsource` because the Content Security Policy allows fonts from `'self'` only. Body text is 16px or larger. Small uppercase labels are tracked at 0.08em.

## Shape

Square corners: `--radius-card: 0`, `--radius-pill: 2px`. This is a standing owner request. One shadow (`--shadow-raise`) lifts the three objects that float: the scan bench, the disguise cards and the flow card. Everything else is flat with a 1px rule.

## Assets: one visual language

| Asset | Source | Where |
|---|---|---|
| Key art | `public/video/heimdall-gate.mp4` and `.webp` poster, cut from the original hero video | Home hero only |
| Figures | Hairline isometric line figures, light theme, navy lines with a blue highlight | Every page header, the Home story |
| Icons | Phosphor, regular weight, imported only through `src/components/icons.js` | Buttons, the layer map, the flow card |
| Logo | Diamond gate with a blue centre point: `src/components/Logo.jsx`, `public/favicon.svg`, `assets/logo/*` | Nav, favicon, app icons, README |

No second icon family, no photographs, no decorative canvas or WebGL backgrounds.

## Components to reuse

`PageHead` (title, sentence, actions, figure) opens every tool page. `SeverityScale` is the only severity display. `Verdict` chips, `ErrorPanel`, `Empty` and `Skeleton` cover every data state. `LayerGrid` is the layer map. Buttons are `.btn` (outline) and `.btn-primary` (navy); labels are a verb and an object.

## Motion

Motion explains something or it is removed. Text is never hidden or dimmed below 4.5:1 by an effect, and caveats such as Known limits are plain, always-visible rows. See `knowledge-base/03-frontend/motion-system.md`. Every effect has a reduced-motion state, hover effects are gated by `(hover: hover) and (pointer: fine)`, and buttons press to `scale(0.97)`.

## Copy

Plain sentences. No em dashes. No invented figures: every number on screen comes from the API or from `public/data/evaluation.json`.
