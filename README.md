![Vitiate](./public/marquee/vitiate.png)

Vitiate is a Manifest V3 browser extension that raises the cost of behavioral profiling. It runs fully locally and gives you per-domain control over how aggressive that should be.

> Vitiate is one layer in a privacy posture. It does not guarantee anonymity, and it does not defeat bot managers that require `isTrusted` events.

Reviewed against browser and tracker behavior as of October 2026.

## What it does

- Jitters timestamps on real `keydown`, `keyup`, `beforeinput`, `pointerdown`, `click`, and `wheel` events without delaying the listeners or reordering them
- Injects a small amount of **untrusted** pointer/mouse noise for naive heatmaps that never check `isTrusted`
- Adds session-stable, low-bit noise to canvas, OffscreenCanvas, WebGL `readPixels`, and audio readbacks (`getChannelData` and `copyFromChannel`)
- Collapses unmasked WebGL and WebGPU adapter strings onto the browser's already-masked GPU identity, and strips high-entropy UA client hints
- Redacts likely PII in outbound telemetry payloads (including common first-party collector paths such as `/g/collect`) without rewriting form submits
- Blocks current third-party behavioral collectors (GA4, product analytics, session replay) without blocking their product dashboards or error monitors such as Sentry
- Tracks session + lifetime metrics in a live popup dashboard

## What it no longer does

These were accurate a few years ago and are counterproductive now:

- Spoofing `navigator.platform`, languages, screen size, `deviceMemory`, or a fake `"Generic Renderer"`. Anti-bot scripts compare those to `userAgentData`, media queries, and WebGPU and treat the mismatch as the signal.
- Dispatching synthetic clicks, keystrokes, or scrolls. They are `isTrusted: false`, current bot managers ignore them, and bubbling fakes can activate real handlers.
- Delaying key and scroll listeners. That desyncs callback time from `timeStamp` and breaks IMEs.
- Rewriting form fields and paste text. That corrupted the request the user meant to send.
- Blocking whole vendor domains (`mixpanel.com`, `sentry.io`) or Universal Analytics-only endpoints.

Defenses run in the page **MAIN** world at `document_start`. An isolated content script cannot patch the prototypes page scripts actually call. Firefox 128+ is required for MAIN-world content scripts.

## Architecture

| Module | File | Responsibility |
|---|---|---|
| Background Service Worker | `src/background/background.ts` | Settings persistence, metrics aggregation, message routing, badge state, client-hint rule |
| Isolated bridge | `src/content/content.ts` | Settings and metrics relay. Does not patch the page. |
| Page-world defenses | `src/content/page-world.ts` | MAIN-world interception, pointer noise, fingerprint readback noise, telemetry redaction |
| Popup UI | `src/popup/popup.ts` | Runtime controls, metrics rendering, activity feed, domain management |
| Shared Types | `src/shared/types.ts` | Cross-module contracts and defaults |

## Project layout

```text
Vitiate/
├── chrome-extension/           # Built unpacked extension
├── firefox-extension/          # Built unpacked Firefox extension
├── public/
│   ├── manifest.json
│   ├── manifest.firefox.json
│   └── icons/
├── src/
│   ├── background/
│   │   └── background.ts
│   ├── content/
│   │   ├── content.ts
│   │   └── page-world.ts
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
npm run build:firefox
```

Then:

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `chrome-extension/` directory

Firefox 128 or newer:

1. Open `about:debugging#/runtime/this-firefox`
2. Click **Load Temporary Add-on**
3. Select `firefox-extension/manifest.json`

## Limits (October 2026)

- Synthetic events cannot be `isTrusted`. Bot managers from Cloudflare, DataDome, HUMAN, and Akamai ignore them. Poisoning is for naive collectors only.
- Prototype hooks are visible via `Function.prototype.toString`. That can raise a bot score. Turn modules off if a site starts challenging you.
- Worker-created canvases are not patched. Fingerprinters that hash a canvas inside a Worker bypass readback noise.
- First-party collectors on unknown paths are not blocked. Known paths (`/g/collect`, `/cdn-cgi/rum`, Matomo) are redacted, not universally blocked.
- Client-hint stripping follows the global fingerprint toggle. Static tracker blocks stay on.
- Do not expect this to replace a browser's own fingerprint resistance (Brave, Firefox RFP) or a separate content blocker.

## Security and runtime constraints

- No external API calls
- No remote code execution
- Strict extension CSP
- Local-only processing path for detection, poisoning, and metrics

## Notes

Use it as one layer in a broader privacy posture.
