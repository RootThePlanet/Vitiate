# Vitiate

Browser extension that actively poisons behavioral data to defend against autonomous AI scraping and biometric profiling.

## Architecture

Vitiate operates as a persistent local firewall between the user and the browser DOM. It injects mathematically sound but flawed behavioral noise into the DOM event stream to confuse hostile AI scrapers while maintaining a seamless user experience.

### Core Modules

| Module | File | Purpose |
|--------|------|---------|
| **Background Service Worker** | `src/background/background.ts` | Settings persistence, metrics aggregation, message routing |
| **Content Script** | `src/content/content.ts` | Event interception, data poisoning, prompt sanitization |
| **Popup UI** | `src/popup/popup.ts` | Dashboard, toggle controls, session activity chart |
| **Shared Types** | `src/shared/types.ts` | TypeScript interfaces shared across all modules |

### Folder Structure

```
vitiate/
├── public/
│   ├── manifest.json          # Manifest V3 configuration
│   └── icons/                 # Extension icons
├── src/
│   ├── background/
│   │   └── background.ts      # Service Worker
│   ├── content/
│   │   └── content.ts         # Content Script (Phases 2–4)
│   ├── popup/
│   │   ├── popup.html         # Popup UI
│   │   ├── popup.css          # Styles
│   │   └── popup.ts           # Popup logic + Chart.js
│   └── shared/
│       └── types.ts           # Shared TypeScript types
├── vite.config.ts
├── tsconfig.json
└── package.json
```

## Features

- **Event Interception** — Hooks `mousemove`, `click`, `keydown`, `keyup`, `scroll`, and `submit` via addEventListener prototype override
- **Data Poisoning** — Generates 3–5 synthetic events per genuine user event using a fast xorshift128+ PRNG
- **Typing Cadence Obfuscation** — Randomises `timeStamp` on key events to defeat inter-keystroke timing analysis
- **Prompt Sanitization** — Regex-based PII detection on textarea/contenteditable elements before submission
- **Per-Domain Control** — Enable/disable protection globally or per-domain
- **Session Dashboard** — Real-time metrics and activity chart in the popup UI

## Development

```bash
# Install dependencies
npm install

# Type-check
npm run typecheck

# Build for production
npm run build

# Watch mode
npm run dev
```

## Loading the Extension

1. Run `npm run build`
2. Open `chrome://extensions/` in Chrome
3. Enable "Developer mode"
4. Click "Load unpacked" and select the `dist/` folder

## Constraints

- **Zero network latency** — All processing is local; no external API calls
- **< 2 ms synthetic event generation** — Uses xorshift128+ PRNG and requestIdleCallback
- **Strict CSP** — `script-src 'self'; object-src 'none'` prevents XSS vectors

