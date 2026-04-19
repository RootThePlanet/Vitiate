![Vitiate](./public/marquee/vitiate.png)

Vitiate is a Manifest V3 browser extension that poisons behavioral telemetry and reduces biometric signal quality for automated scraping systems.

It runs fully locally, adds controlled noise to event streams, and gives you per-domain control over how aggressive the protection should be.

> Vitiate is built to raise the cost of behavioral profiling — not to guarantee anonymity.

## What it does

- Intercepts high-signal browser events (`mousemove`, `click`, `keydown`, `keyup`, `scroll`, `submit`)
- Injects synthetic noise events with intensity-aware profiles
- Obfuscates keystroke timing fingerprints
- Sanitizes likely PII patterns in form and paste flows
- Poisons common canvas / WebGL fingerprinting paths
- Spoofs select navigator/screen fingerprinting properties
- Tracks session + lifetime metrics in a live popup dashboard

## Architecture

| Module | File | Responsibility |
|---|---|---|
| Background Service Worker | `src/background/background.ts` | Settings persistence, metrics aggregation, message routing, badge state |
| Content Script | `src/content/content.ts` | Event interception, poisoning engine, sanitization, fingerprint defenses |
| Popup UI | `src/popup/popup.ts` | Runtime controls, metrics rendering, activity feed, domain management |
| Shared Types | `src/shared/types.ts` | Cross-module contracts and defaults |

## Project layout

```text
Vitiate/
├── chrome-extension/           # Built unpacked extension
├── public/
│   ├── manifest.json
│   └── icons/
├── src/
│   ├── background/
│   │   └── background.ts
│   ├── content/
│   │   └── content.ts
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.ts
│   └── shared/
│       └── types.ts
├── tsconfig.json
├── vite.config.ts
└── package.json
```

## Quick start

```bash
npm install
npm run typecheck
npm run build
```

Then:

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `chrome-extension/` directory

## Security and runtime constraints

- No external API calls
- No remote code execution
- Strict extension CSP
- Local-only processing path for detection, poisoning, and metrics

## Notes

Use it as one layer in a broader privacy posture.
