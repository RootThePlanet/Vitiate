/**
 * Vitiate — Content Script
 * Injected at document_start on every frame.
 *
 * Phase 2: Event Interception Layer
 * Phase 3: Data Poisoning Engine
 * Phase 4: Semantic Prompt Sanitization
 *
 * All processing is local with zero network I/O.
 */

import type { VitiateMessage, TrackedEventType } from "../shared/types";

/* ================================================================== */
/*  Configuration                                                      */
/* ================================================================== */

const TRACKED_EVENTS: TrackedEventType[] = [
  "mousemove",
  "click",
  "keydown",
  "keyup",
  "scroll",
  "submit",
];

/** Number of synthetic events per genuine event (3–5, randomised) */
const MIN_SYNTHETIC = 3;
const MAX_SYNTHETIC = 5;

/** Maximum queued synthetic events to prevent memory bloat */
const MAX_QUEUE = 512;

/** Flush interval for batched metric reports (ms) */
const METRICS_FLUSH_MS = 5_000;

/* ================================================================== */
/*  Runtime state                                                      */
/* ================================================================== */

let engineEnabled = true;
let pendingIntercepted = 0;
let pendingSynthetic = 0;
let pendingSanitized = 0;

/* ================================================================== */
/*  Utility: fast seeded PRNG (xorshift128+)                           */
/* ================================================================== */

let _s0 = (Math.random() * 0xffffffff) >>> 0;
let _s1 = (Math.random() * 0xffffffff) >>> 0;

function xorshift128plus(): number {
  let s1 = _s0;
  const s0 = _s1;
  _s0 = s0;
  s1 ^= s1 << 23;
  s1 ^= s1 >>> 17;
  s1 ^= s0;
  s1 ^= s0 >>> 26;
  _s1 = s1;
  // Normalize to [0, 1)
  return ((_s0 + _s1) >>> 0) / 0x100000000;
}

function randInt(min: number, max: number): number {
  return min + Math.floor(xorshift128plus() * (max - min + 1));
}

function randFloat(min: number, max: number): number {
  return min + xorshift128plus() * (max - min);
}

/* ================================================================== */
/*  Phase 2: Event Interception Layer                                  */
/* ================================================================== */

/**
 * Override addEventListener on both Window.prototype and
 * Document.prototype so third-party tracking scripts receive
 * poisoned payloads instead of raw user telemetry.
 *
 * We wrap the listener callback, not the registration itself,
 * so legitimate site functionality (e.g. React event handlers)
 * continues to work.  Only tracked event types are intercepted.
 */

const trackedSet = new Set<string>(TRACKED_EVENTS);

/**
 * Sentinel to mark our own synthetic dispatches so they are
 * not re-intercepted (avoids infinite loops).
 */
const SYNTHETIC_KEY = "__vitiate_synthetic__";

type AnyListener = EventListenerOrEventListenerObject;
type OriginalAddEventListener = typeof EventTarget.prototype.addEventListener;

function patchAddEventListener(proto: EventTarget): void {
  const original: OriginalAddEventListener = proto.addEventListener;

  proto.addEventListener = function (
    type: string,
    listener: AnyListener | null,
    options?: boolean | AddEventListenerOptions,
  ): void {
    if (!listener) {
      return original.call(this, type, listener, options);
    }

    if (!trackedSet.has(type)) {
      // Non-tracked event — pass through untouched
      return original.call(this, type, listener, options);
    }

    // Wrap the listener to inject poisoned data
    const wrappedListener: EventListener = (evt: Event) => {
      if (!engineEnabled || (evt as unknown as Record<string, unknown>)[SYNTHETIC_KEY]) {
        // Pass synthetic events or when engine disabled
        if (typeof listener === "function") {
          listener(evt);
        } else {
          listener.handleEvent(evt);
        }
        return;
      }

      pendingIntercepted++;

      // Deliver the (optionally mutated) original event
      const mutated = maybeMutateTimestamp(evt);
      if (typeof listener === "function") {
        listener(mutated);
      } else {
        listener.handleEvent(mutated);
      }
    };

    return original.call(this, type, wrappedListener, options);
  };
}

// Apply patches
patchAddEventListener(Window.prototype);
patchAddEventListener(Document.prototype);
patchAddEventListener(Element.prototype);

/* ================================================================== */
/*  Phase 3: Data Poisoning Engine                                     */
/* ================================================================== */

/**
 * Typing cadence obfuscator — randomise timeStamp on key events
 * before they reach third-party listeners.  We create a proxy of
 * the original event with an overridden timeStamp to avoid
 * mutating the frozen native Event object.
 */
function maybeMutateTimestamp(evt: Event): Event {
  if (evt.type !== "keydown" && evt.type !== "keyup") return evt;

  // Jitter ±15 ms to defeat inter-keystroke timing analysis
  const jitter = randFloat(-15, 15);
  return new Proxy(evt, {
    get(target, prop) {
      if (prop === "timeStamp") {
        return Math.max(0, target.timeStamp + jitter);
      }
      const value = Reflect.get(target, prop);
      if (typeof value === "function") {
        return value.bind(target);
      }
      return value;
    },
  });
}

/**
 * Synthetic event generator.
 * Upon each genuine tracked event, produce 3–5 plausible but
 * fake events and dispatch them into the DOM so AI scrapers
 * ingest corrupted biometric signals.
 *
 * Performance target: < 2 ms per invocation.
 */

const syntheticQueue: Event[] = [];
let flushScheduled = false;

function scheduleSyntheticFlush(): void {
  if (flushScheduled) return;
  flushScheduled = true;
  // Use requestIdleCallback when available for non-blocking dispatch
  if (typeof requestIdleCallback !== "undefined") {
    requestIdleCallback(flushSyntheticQueue, { timeout: 50 });
  } else {
    setTimeout(flushSyntheticQueue, 0);
  }
}

function flushSyntheticQueue(): void {
  flushScheduled = false;
  const target = document.documentElement ?? document.body;
  if (!target) return;

  while (syntheticQueue.length > 0) {
    const evt = syntheticQueue.shift()!;
    try {
      target.dispatchEvent(evt);
    } catch {
      // Swallow errors from synthetic dispatch to avoid breaking pages
    }
  }
}

function generateSyntheticMouseMove(baseEvent: MouseEvent): MouseEvent {
  return new MouseEvent("mousemove", {
    clientX: baseEvent.clientX + randInt(-80, 80),
    clientY: baseEvent.clientY + randInt(-80, 80),
    screenX: baseEvent.screenX + randInt(-80, 80),
    screenY: baseEvent.screenY + randInt(-80, 80),
    movementX: randInt(-20, 20),
    movementY: randInt(-20, 20),
    bubbles: true,
    cancelable: true,
  });
}

function generateSyntheticClick(baseEvent: MouseEvent): MouseEvent {
  return new MouseEvent("click", {
    clientX: baseEvent.clientX + randInt(-30, 30),
    clientY: baseEvent.clientY + randInt(-30, 30),
    button: 0,
    bubbles: true,
    cancelable: true,
  });
}

function generateSyntheticKey(
  type: "keydown" | "keyup",
  baseEvent: KeyboardEvent,
): KeyboardEvent {
  // Use a randomised key from a plausible character set
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789 ";
  const key = chars[randInt(0, chars.length - 1)];
  return new KeyboardEvent(type, {
    key,
    code: `Key${key.toUpperCase()}`,
    bubbles: true,
    cancelable: true,
  });
}

function generateSyntheticScroll(): Event {
  return new Event("scroll", { bubbles: true, cancelable: false });
}

function enqueueSynthetics(evt: Event): void {
  if (!engineEnabled) return;
  if (syntheticQueue.length >= MAX_QUEUE) return;

  const count = randInt(MIN_SYNTHETIC, MAX_SYNTHETIC);

  for (let i = 0; i < count; i++) {
    let synthetic: Event | null = null;

    switch (evt.type) {
      case "mousemove":
        synthetic = generateSyntheticMouseMove(evt as MouseEvent);
        break;
      case "click":
        synthetic = generateSyntheticClick(evt as MouseEvent);
        break;
      case "keydown":
        synthetic = generateSyntheticKey("keydown", evt as KeyboardEvent);
        break;
      case "keyup":
        synthetic = generateSyntheticKey("keyup", evt as KeyboardEvent);
        break;
      case "scroll":
        synthetic = generateSyntheticScroll();
        break;
      // submit events are intercepted but not synthetically replicated
      // to avoid unintended form submissions
    }

    if (synthetic) {
      (synthetic as unknown as Record<string, unknown>)[SYNTHETIC_KEY] = true;
      syntheticQueue.push(synthetic);
      pendingSynthetic++;
    }
  }

  scheduleSyntheticFlush();
}

/**
 * Attach top-level event delegation listeners on the document.
 * These fire on every genuine event and feed the poisoning engine.
 */
function attachEventDelegation(): void {
  for (const eventType of TRACKED_EVENTS) {
    document.addEventListener(
      eventType,
      (evt: Event) => {
        if ((evt as unknown as Record<string, unknown>)[SYNTHETIC_KEY]) return;
        enqueueSynthetics(evt);
      },
      { capture: true, passive: true },
    );
  }
}

/* ================================================================== */
/*  Phase 4: Semantic Prompt Sanitization                              */
/* ================================================================== */

/**
 * Lightweight regex-based PII patterns for immediate sanitization.
 * These run entirely client-side with zero network overhead.
 *
 * Architecture note — future WASM NLP integration:
 * -----------------------------------------------
 * For robust semantic analysis beyond regex (e.g. detecting
 * behavioural markers, writing-style fingerprints, or
 * context-dependent PII), a WebAssembly-compiled NLP model
 * can be loaded here:
 *
 * 1. Compile a lightweight transformer (e.g. distilled BERT)
 *    to WASM using emscripten / wasm-pack.
 * 2. Load the .wasm binary from extension assets via
 *    chrome.runtime.getURL("models/sanitizer.wasm").
 * 3. Initialize the model in a dedicated Web Worker to avoid
 *    blocking the main thread.
 * 4. Replace or augment sanitizeText() below with model inference,
 *    returning sanitized text asynchronously.
 * 5. Keep regex rules as a fast-path pre-filter; only invoke the
 *    WASM model when the regex pre-filter flags ambiguous content.
 */

const PII_PATTERNS: { pattern: RegExp; replacement: string }[] = [
  // Email addresses
  {
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    replacement: "[email redacted]",
  },
  // Phone numbers (US / international formats)
  {
    pattern: /(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}/g,
    replacement: "[phone redacted]",
  },
  // Social Security Numbers (US)
  {
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    replacement: "[SSN redacted]",
  },
  // Credit card numbers (basic)
  {
    pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    replacement: "[card redacted]",
  },
  // IP addresses (IPv4)
  {
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    replacement: "[IP redacted]",
  },
  // Physical addresses (simplified US-style)
  {
    pattern: /\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct)\b/gi,
    replacement: "[address redacted]",
  },
];

function sanitizeText(text: string): { sanitized: string; changed: boolean } {
  let result = text;
  let changed = false;
  for (const { pattern, replacement } of PII_PATTERNS) {
    // Reset regex state for global patterns
    pattern.lastIndex = 0;
    if (pattern.test(result)) {
      changed = true;
      pattern.lastIndex = 0;
      result = result.replace(pattern, replacement);
    }
  }
  return { sanitized: result, changed };
}

/**
 * Observe textareas and contenteditable elements for PII leakage.
 * We intercept at the "beforeinput" / "submit" boundary so the user
 * sees their original text but outbound payloads are sanitized.
 */
function attachPromptSanitization(): void {
  // Intercept form submissions
  document.addEventListener(
    "submit",
    (evt: Event) => {
      const form = evt.target as HTMLFormElement;
      if (!form || !engineEnabled) return;

      const textInputs = form.querySelectorAll<
        HTMLTextAreaElement | HTMLInputElement
      >("textarea, input[type='text'], input[type='search']");

      for (const input of textInputs) {
        const { sanitized, changed } = sanitizeText(input.value);
        if (changed) {
          input.value = sanitized;
          pendingSanitized++;
        }
      }

      // Also sanitize contenteditable within the form
      const editables = form.querySelectorAll<HTMLElement>("[contenteditable='true']");
      for (const el of editables) {
        const { sanitized, changed } = sanitizeText(el.innerText);
        if (changed) {
          el.innerText = sanitized;
          pendingSanitized++;
        }
      }
    },
    { capture: true },
  );

  // Monitor dynamic textareas / contenteditable elements via MutationObserver
  const observer = new MutationObserver((mutations) => {
    if (!engineEnabled) return;
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node instanceof HTMLElement) {
          attachInputWatcher(node);
        }
      }
    }
  });

  observer.observe(document.documentElement ?? document.body, {
    childList: true,
    subtree: true,
  });
}

/**
 * Attach a "paste" sanitizer to a single input-like element.
 * This prevents pasting PII into LLM chat interfaces.
 */
function attachInputWatcher(root: HTMLElement): void {
  const targets = [
    ...root.querySelectorAll<HTMLElement>(
      "textarea, [contenteditable='true']",
    ),
  ];
  if (
    root.matches("textarea") ||
    root.getAttribute("contenteditable") === "true"
  ) {
    targets.push(root);
  }

  for (const el of targets) {
    if ((el as unknown as Record<string, unknown>).__vitiate_watched__) continue;
    (el as unknown as Record<string, unknown>).__vitiate_watched__ = true;

    el.addEventListener("paste", (evt: Event) => {
      if (!engineEnabled) return;
      const clipboardEvt = evt as ClipboardEvent;
      const text = clipboardEvt.clipboardData?.getData("text/plain");
      if (!text) return;

      const { sanitized, changed } = sanitizeText(text);
      if (changed) {
        evt.preventDefault();
        // Insert the sanitized text instead
        document.execCommand("insertText", false, sanitized);
        pendingSanitized++;
      }
    });
  }
}

/* ================================================================== */
/*  Metrics reporting                                                  */
/* ================================================================== */

function flushMetrics(): void {
  if (
    pendingIntercepted === 0 &&
    pendingSynthetic === 0 &&
    pendingSanitized === 0
  ) {
    return;
  }

  const msg: VitiateMessage = {
    type: "REPORT_METRICS",
    delta: {
      interceptedEvents: pendingIntercepted,
      syntheticEventsInjected: pendingSynthetic,
      sanitizedInputs: pendingSanitized,
    },
  };

  chrome.runtime.sendMessage(msg).catch(() => {
    // Extension context may have been invalidated — ignore
  });

  pendingIntercepted = 0;
  pendingSynthetic = 0;
  pendingSanitized = 0;
}

/* ================================================================== */
/*  Initialisation                                                     */
/* ================================================================== */

async function init(): Promise<void> {
  // Fetch current settings from the background SW
  try {
    const response = (await chrome.runtime.sendMessage({
      type: "GET_SETTINGS",
      domain: location.hostname,
    } satisfies VitiateMessage)) as VitiateMessage;

    if (response?.type === "SETTINGS_RESPONSE") {
      engineEnabled = response.domainEnabled;
    }
  } catch {
    // First run or extension context invalid — default to enabled
    engineEnabled = true;
  }

  attachEventDelegation();
  attachPromptSanitization();

  // Periodically flush metrics
  setInterval(flushMetrics, METRICS_FLUSH_MS);
}

init();
