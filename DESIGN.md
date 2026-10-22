# Design notes

## Direction

The dashboard is a system utility, not a marketing page. The reference direction is the
Apple system settings and storage utilities: grouped solid surfaces, one accent, system
type, compact status language, and controls sized for touch. The implementation borrows
those traits only. It does not use Apple assets, logos, screenshots, or copied layouts.

The page is deliberately quiet. An integrity monitor is read when something is wrong, so
the useful information is the overall state, the last scan, and the path-level changes.
Everything else is secondary.

## Dials

| Dial | Value | Meaning |
| ---- | ----- | ------- |
| Energy | 1 | Calm surfaces, one accent, no decorative color |
| Rhythm | 1 | One page, one status block, one list |
| Motion | 2 | Functional state transitions, scan indicator, one alert entrance |

No scroll animation, parallax, hover tilt, or decorative motion.

## Tokens

### Color

| Token | Light | Dark | Usage |
| ----- | ----- | ---- | ----- |
| `--bg` | `#f5f5f7` | `#0b0b0d` | Page background |
| `--surface` | `#ffffff` | `#161618` | Panels and rows |
| `--text` | `#1d1d1f` | `#f5f5f7` | Primary text |
| `--muted` | `#55555a` | `#b0b0b5` | Body and secondary text |
| `--faint` | `#6e6e73` | `#98989d` | Metadata |
| `--line` | `rgba(0,0,0,.09)` | `rgba(255,255,255,.10)` | Dividers |
| `--accent` | `#0071e3` | `#409cff` | Focus, selected filter, primary action |
| `--green` | `#1f7a33` | `#30d158` | Protected state |
| `--amber` | `#8a5200` | `#ffd60a` | Added and modified states |
| `--red` | `#b3261e` | `#ff6961` | Deleted and error states |

Measured contrast:

| Pair | Ratio |
| ---- | ----- |
| Light text on background | 15.46:1 |
| Light text on surface | 16.83:1 |
| Light muted on background | 6.81:1 |
| Light faint on background | 4.66:1 |
| Light button text on accent | 4.70:1 |
| Dark text on background | 18.06:1 |
| Dark text on surface | 16.60:1 |
| Dark muted on background | 9.11:1 |
| Dark faint on background | 6.85:1 |

All body and metadata pairs meet WCAG AA for normal text. State color is never the only
signal: each alert row also has a text kind and each metric has a label.

### Typography

- Family: `-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto,
  "Helvetica Neue", Arial, sans-serif`. System stack only, no web font request.
- Monospace is used for paths and hashes because those values need character alignment,
  not for decoration.
- Base text: 15px / 1.5.
- Display: 19px / 1.1 for the wordmark, 26px to 30px for the page state.
- Metadata: 12px to 13px.

### Spacing and shape

- Base unit: 4px.
- Common steps: 4, 8, 12, 16, 20, 24, 28, 32, 40, 48, 72.
- Page shell: maximum 1120px, 24px side padding, 72px bottom padding.
- Surface radius: 20px.
- Control radius: 999px.
- Badge radius: 7px.
- Shadow is used only to lift a surface from the page background. There is no shadow on
  text, buttons, or every row.

## Layout

- A single column at every width.
- Top bar: wordmark, scan action, theme control.
- State block: status, last check, added/modified/deleted/errors.
- Alerts block: filter row, then a list of paths.
- On mobile, filters become a 2x2 grid. Rows stack path above metadata.
- No sidebar, tab bar, card grid, logo strip, pricing block, or hero.

## Interaction

- Filters are a four-way segmented control. The selected filter uses accent-soft fill,
  an accent border, and primary text. It is not conveyed by color alone.
- The theme button is `aria-pressed`. It persists in `localStorage` and updates the
  `theme-color` meta tag.
- The scan button enters a busy state with `disabled` and the label `Scanning`. A manual
  scan is single-flight.
- Loading uses three skeleton rows and a `Connecting` state. Filter changes during loading
  do not replace the skeletons with an empty list.
- Empty and error states have a title, one sentence, and a next step. Offline errors keep
  retrying automatically.
- The alert entrance is a short opacity and translate transition. Reduced motion is
  respected through the global media query.
- Keyboard order follows the visual order. The skip link targets `#main`. Focus uses a
  2px accent outline with 3px offset.

## Anti-slop review

Rejected on purpose:

- No purple or blue gradient orbs, gradient text, or blurred background decoration.
- No glassmorphism, neon borders, or permanent dark mode. Light is the default; dark
  follows the system or the explicit toggle.
- No generic hero, three-card feature grid, bento grid, logo strip, or "1 2 3" steps.
- No stock Tailwind or shadcn palette. The palette is defined above.
- No custom logo or favicon was invented. `/favicon.ico` returns `204`.
- No Inter, Poppins, Space Grotesk, or Geist. The system stack is intentional.
- No decorative serif italic accent and no decorative monospace.
- No micro-label above every number. The four metric labels are required to distinguish
  added, modified, deleted, and errors.
- No external assets, analytics, tracking pixels, or outbound requests.

## Verification evidenced

Tool: Playwright with headless Chromium at `/usr/bin/chromium` against the real Axum
server. Reticle could not instrument this page because it is static HTML served by a Rust
binary, so Playwright is the browser evidence here.

Final run: 2026-10-22, report at `/tmp/opencode/final-report.json`.

| Check | Result |
| ----- | ------ |
| Console errors | `[]` |
| Page errors | `[]` |
| HTTP errors | `[]` |
| Main state | `Changes found`, 4 unique alert rows, metrics `1 / 2 / 1 / 0` |
| Loading | 3 skeletons, `Connecting`, `Loading`; still 3 skeletons after a filter click |
| Empty | `Protected`, `No anomalies recorded`, 0 rows, no error banner |
| Offline | `Offline`, `Cannot reach the RPI-AIDE API. Retrying automatically.`, `Status API unreachable` |
| Filters | Added, modified, deleted, and all return the expected rows |
| Theme | Light to dark to light from the top bar and keyboard; `aria-pressed` follows |
| Keyboard | Skip link reaches `#main`; focus outline is `2px solid`; tab order is visual order |
| Scan | Busy label `Scanning`, button disabled, then status returns and rows remain |
| Root disclosure | Roots list opens and shows the configured root |
| Mobile 390 | No horizontal overflow, filter grid, four 44px controls |
| Mobile 360 | No horizontal overflow, filter grid, four 44px controls |
| Mobile 320 | No horizontal overflow, filter grid, four 44px controls |
| Scan CSRF | `POST /api/scan` without `x-rpi-aide-scan: 1` returns `403`; with it returns `202` |

## Delivery gate

- [x] No unexplained gradients, orbs, glass, neon, or 3D decoration
- [x] Not the default shadcn or Tailwind palette
- [x] Not the templated hero, three-card, logo strip, pricing, FAQ structure
- [x] No unnecessary micro-label above every value
- [x] System stack, not a default AI font
- [x] Contrast, 44px controls, visible focus, skip link, reduced motion
- [x] No invented logo or favicon
- [x] No horizontal overflow at 390, 360, or 320
- [x] Loading, empty, error, busy, and offline states verified
