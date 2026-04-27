# Vitiate — Privacy Policy

**Applies to:** Vitiate for Google Chrome and Mozilla Firefox  
**Extension version:** 1.2.0 and later  
**Last updated:** 2026-04-27

---

## Overview

Vitiate is a browser extension that runs entirely on your device. Its purpose is to poison behavioral telemetry and reduce biometric signal quality collected by websites. It does **not** collect, transmit, or share any personal data.

---

## Data We Do Not Collect

Vitiate never:

- Sends any data to external servers, APIs, or third-party services.
- Collects personally identifiable information (PII) of any kind.
- Tracks your browsing history, visited URLs, or search queries.
- Reads, records, or transmits the content of web pages you visit.
- Stores your keystrokes, form input values, or clipboard contents.
- Uses analytics, crash-reporting services, or advertising networks.

There is **no network I/O** in the extension. All processing happens locally on your device.

---

## What the Extension Accesses

Vitiate requires the following browser permissions to function:

| Permission | Purpose |
|---|---|
| `activeTab` | Identify the current domain so per-site protection settings can be applied. |
| `storage` | Persist your settings and cumulative metrics locally on your device. |
| `host_permissions: <all_urls>` | Inject the content script on any page so behavioral telemetry can be intercepted and poisoned. |

---

## Local Storage

Vitiate uses `chrome.storage.local` (Chrome) and `browser.storage.local` (Firefox) — both of which are sandboxed to the extension and never synchronized to any remote service — to store:

| Key | Contents |
|---|---|
| `vitiate_settings` | Your preferences: global on/off toggle, per-domain overrides, intensity level, and module policy. |
| `vitiate_lifetime` | Cumulative counters: total intercepted events, synthetic events injected, and sanitized inputs. These are aggregate numbers only — no event content is stored. |

This data never leaves your device. You can clear it at any time by removing the extension or using your browser's extension storage tools.

---

## What the Extension Does to Web Page Content

To protect you from behavioral profiling, Vitiate modifies how the browser reports certain signals **within the page** (not outside it):

- **Event interception** — Intercepts `mousemove`, `click`, `keydown`, `keyup`, `scroll`, and `submit` events and adds timing jitter before they reach tracking scripts.
- **Synthetic event injection** — Injects artificial noise events to make behavioral fingerprints less reliable.
- **Fingerprint spoofing** — Overrides canvas, WebGL, `navigator`, and `screen` properties with coherent but fictitious values to disrupt device fingerprinting.
- **PII sanitization** — Detects likely PII patterns (e.g. email addresses, phone numbers) in form fields and paste flows and replaces them with plausible synthetic data before they are read by tracking scripts.

None of this data is read by Vitiate for its own purposes; the extension modifies these signals in-page to protect you and then discards them.

---

## Diagnostics Snapshot

The popup provides an optional **Export Snapshot** feature that creates a local JSON file containing your settings, session counters, and error logs. This file is downloaded directly to your device. It is never transmitted anywhere. You control when and whether to export it.

---

## Children's Privacy

Vitiate does not collect any data from any user, including children. The extension has no account system, no registration, and no user-facing data submission of any kind.

---

## Changes to This Policy

If this policy is updated, the new version will be committed to the [Vitiate repository](https://github.com/RootThePlanet/Vitiate) and the **Last updated** date above will change. Continued use of the extension after an update constitutes acceptance of the revised policy.

---

## Contact

Questions about this policy can be raised by opening an issue in the [Vitiate GitHub repository](https://github.com/RootThePlanet/Vitiate/issues).
