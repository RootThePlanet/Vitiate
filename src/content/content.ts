/**
 * Vitiate — Content Script  v2
 * Injected at document_start on every frame.
 *
 * Defense Pipeline:
 *   Module 1 — Interception  : addEventListener patching + timestamp jitter
 *   Module 2 — Poisoning     : synthetic event injection (token-bucket rate-limited,
 *                               Gaussian behavioral templates, sensitive-page guardrails)
 *   Module 3 — Fingerprint   : canvas/WebGL/navigator/screen spoofing
 *                               (coherent cross-property bundle)
 *   Module 4 — Sanitization  : PII redaction in form submit + paste events
 *
 * v2 additions vs. v1:
 * - Coherent fingerprint bundle (properties generated together per platform profile)
 * - Gaussian noise for realistic mouse arc templates
 * - Letter-frequency key distribution for synthetic keystrokes
 * - Token-bucket adaptive rate limiter (prevents CPU/latency spikes)
 * - Sensitive-page guardrails (password / payment pages disable poisoning)
 * - Per-module counters with background reporting
 * - Site-compatibility incident reporting
 * - ModulePolicy awareness (each module checks its enabled flag)
 *
 * All processing is local with zero network I/O.
 */

import {
  type VitiateMessage,
  type TrackedEventType,
  type IntensityLevel,
  type IntensityConfig,
  type ActivityEntry,
  type ModuleId,
  type ModulePolicy,
  type FingerprintBundle,
  type ModuleCounter,
  INTENSITY_CONFIGS,
  defaultModuleCounter,
} from "../shared/types";

/* ================================================================== */
/*  Configuration constants                                            */
/* ================================================================== */

const TRACKED_EVENTS: TrackedEventType[] = [
  "mousemove",
  "click",
  "keydown",
  "keyup",
  "scroll",
  "submit",
];

/** Maximum queued synthetic events to prevent memory bloat */
const MAX_QUEUE = 512;

/** Flush interval for batched metric + counter reports (ms) */
const METRICS_FLUSH_MS = 5_000;

/** Maximum buffered activity entries before flush */
const MAX_ACTIVITY_BUFFER = 20;

/** URL / hostname pattern that indicates a sensitive (payment / auth) page */
const SENSITIVE_URL_RE = /bank|pay(?:ment|pal)?|checkout|billing|wallet|finance|credit|transaction|signin|login|auth/i;

/** Marker property name stamped onto synthetic events so wrappers can skip them */
const SYNTHETIC_KEY = "__vitiate_synthetic__";

/** Returns true if the event was created by Vitiate (not real user input). */
function isSynthetic(evt: Event): boolean {
  return (evt as unknown as Record<string, unknown>)[SYNTHETIC_KEY] === true;
}

/** Stamps the Vitiate synthetic marker onto an event in-place. */
function markSynthetic(evt: Event): void {
  (evt as unknown as Record<string, unknown>)[SYNTHETIC_KEY] = true;
}

/* ================================================================== */
/*  Runtime state                                                      */
/* ================================================================== */

let engineEnabled     = true;
let currentIntensity: IntensityLevel = "medium";
let intensityConfig:  IntensityConfig = INTENSITY_CONFIGS.medium;
let effectivePolicy:  ModulePolicy = { intercept: true, poison: true, fingerprint: true, sanitize: true };

let pendingIntercepted = 0;
let pendingSynthetic   = 0;
let pendingSanitized   = 0;
let activityBuffer: ActivityEntry[] = [];
let sensitiveContext   = false;

/* Per-module counters — flushed to background in each metrics batch */
const localCounters: Record<ModuleId, ModuleCounter> = {
  intercept:   defaultModuleCounter(),
  poison:      defaultModuleCounter(),
  fingerprint: defaultModuleCounter(),
  sanitize:    defaultModuleCounter(),
};

/* ================================================================== */
/*  PRNG — xorshift128+                                               */
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
  return ((_s0 + _s1) >>> 0) / 0x100000000;
}

function randInt(min: number, max: number): number {
  return min + Math.floor(xorshift128plus() * (max - min + 1));
}

function randFloat(min: number, max: number): number {
  return min + xorshift128plus() * (max - min);
}

/** Box-Muller transform for Gaussian-distributed random values */
function randGaussian(mean: number, std: number): number {
  const u1 = Math.max(xorshift128plus(), 1e-10);
  const u2 = xorshift128plus();
  const z  = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return mean + z * std;
}

/* ================================================================== */
/*  Token-bucket rate limiter                                          */
/* ================================================================== */

const tokenBucket = {
  tokens:      0,
  lastRefillMs: 0,
};

function consumeToken(): boolean {
  const nowMs    = Date.now();
  const elapsed  = (nowMs - tokenBucket.lastRefillMs) / 1000;
  tokenBucket.tokens = Math.min(
    intensityConfig.tokenBucketMax,
    tokenBucket.tokens + elapsed * intensityConfig.tokenRefillRate,
  );
  tokenBucket.lastRefillMs = nowMs;

  if (tokenBucket.tokens >= 1) {
    tokenBucket.tokens -= 1;
    return true;
  }
  return false;
}

/* ================================================================== */
/*  Activity feed helpers                                              */
/* ================================================================== */

function pushActivity(kind: ActivityEntry["kind"], detail: string): void {
  activityBuffer.push({ time: new Date().toISOString(), kind, detail });
  if (activityBuffer.length >= MAX_ACTIVITY_BUFFER) flushActivity();
}

function flushActivity(): void {
  if (activityBuffer.length === 0) return;
  const entries = activityBuffer.splice(0);
  chrome.runtime.sendMessage({ type: "REPORT_ACTIVITY", entries } satisfies VitiateMessage).catch(() => {});
}

/* ================================================================== */
/*  Module observability helpers                                       */
/* ================================================================== */

function trackSuccess(module: ModuleId): void {
  localCounters[module].processed++;
  localCounters[module].lastActiveMs = Date.now();
}

function trackError(module: ModuleId, err: unknown): void {
  localCounters[module].errors++;
  const msg = err instanceof Error ? err.message : String(err);
  reportIncident(module, msg.slice(0, 120));
}

function trackRateLimit(module: ModuleId): void {
  localCounters[module].skippedRateLimit++;
}

function reportIncident(module: ModuleId, message: string): void {
  chrome.runtime.sendMessage({
    type: "REPORT_INCIDENT",
    incident: { time: new Date().toISOString(), domain: location.hostname, module, message },
  } satisfies VitiateMessage).catch(() => {});
}

/* ================================================================== */
/*  Sensitive-page detection                                           */
/* ================================================================== */

function checkSensitiveContext(): void {
  const wasSensitive = sensitiveContext;

  const urlHit = SENSITIVE_URL_RE.test(location.hostname) || SENSITIVE_URL_RE.test(location.pathname);
  const hasPassword = document.querySelector('input[type="password"]') !== null;
  const hasOTP      = document.querySelector('[autocomplete="one-time-code"]') !== null;

  sensitiveContext = urlHit || hasPassword || hasOTP;

  if (sensitiveContext && !wasSensitive) {
    reportIncident("poison", "Sensitive page detected — synthetic injection paused for this frame");
    pushActivity("error", "Sensitive context detected — poisoning paused");
  }
}

/* ================================================================== */
/*  Module 3 — Fingerprint: coherent bundle                           */
/* ================================================================== */

interface PlatformProfile {
  platform: string;
  screens: [number, number][];
  concurrencies: number[];
  memories: number[];
  colorDepths: number[];
  languageSets: string[][];
}

const PLATFORM_PROFILES: PlatformProfile[] = [
  {
    platform: "Win32",
    screens: [[1920, 1080], [2560, 1440], [1366, 768], [1536, 864], [1280, 720]],
    concurrencies: [4, 8, 12, 16],
    memories: [4, 8, 16],
    colorDepths: [24, 32],
    languageSets: [
      ["en-US", "en"],
      ["en-GB", "en"],
      ["de-DE", "de", "en"],
      ["fr-FR", "fr", "en"],
      ["es-ES", "es"],
    ],
  },
  {
    platform: "MacIntel",
    screens: [[1440, 900], [1680, 1050], [2560, 1440], [2560, 1600], [1920, 1080]],
    concurrencies: [4, 8, 12],
    memories: [8, 16],
    colorDepths: [30, 32],
    languageSets: [
      ["en-US", "en"],
      ["en-GB", "en"],
      ["de-DE", "de", "en"],
    ],
  },
  {
    platform: "Linux x86_64",
    screens: [[1920, 1080], [2560, 1440], [1366, 768], [1280, 1024]],
    concurrencies: [4, 8],
    memories: [4, 8, 16],
    colorDepths: [24],
    languageSets: [
      ["en-US", "en"],
      ["de-DE", "de"],
      ["fr-FR", "fr"],
      ["zh-CN", "zh"],
      ["ja-JP", "ja"],
    ],
  },
];

/** Build a coherent cross-property fingerprint bundle for this session. */
function buildCoherentFingerprintBundle(): FingerprintBundle {
  const profile      = PLATFORM_PROFILES[randInt(0, PLATFORM_PROFILES.length - 1)];
  const [sw, sh]     = profile.screens[randInt(0, profile.screens.length - 1)];
  const languages    = profile.languageSets[randInt(0, profile.languageSets.length - 1)];
  return {
    platform:            profile.platform,
    languages,
    hardwareConcurrency: profile.concurrencies[randInt(0, profile.concurrencies.length - 1)],
    deviceMemory:        profile.memories[randInt(0, profile.memories.length - 1)],
    screenWidth:         sw,
    screenHeight:        sh,
    colorDepth:          profile.colorDepths[randInt(0, profile.colorDepths.length - 1)],
    canvasNoiseSeed:     randInt(1, 65535),
  };
}

/** Session-stable fingerprint bundle — generated once at init. */
let fpBundle: FingerprintBundle = buildCoherentFingerprintBundle();

function applyFingerprintModule(): void {
  if (!effectivePolicy.fingerprint) return;

  try {
    poisonCanvasFingerprint(fpBundle.canvasNoiseSeed);
    spoofNavigatorAndScreen(fpBundle);
    trackSuccess("fingerprint");
  } catch (err) {
    trackError("fingerprint", err);
  }
}

/** Inject deterministic per-session noise into canvas fingerprinting APIs. */
function poisonCanvasFingerprint(noiseSeed: number): void {
  // -- toDataURL --
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function (
    ...args: Parameters<typeof origToDataURL>
  ): string {
    if (!engineEnabled || !effectivePolicy.fingerprint) return origToDataURL.apply(this, args);
    try {
      if (this.width > 0 && this.height > 0) {
        const tmp = document.createElement("canvas");
        tmp.width = this.width;
        tmp.height = this.height;
        const ctx = tmp.getContext("2d");
        if (ctx) {
          ctx.drawImage(this, 0, 0);
          const img = ctx.getImageData(0, 0, 1, 1);
          img.data[0] = (img.data[0] + noiseSeed) & 0xff;
          ctx.putImageData(img, 0, 0);
          return origToDataURL.apply(tmp, args);
        }
      }
    } catch { /* tainted or zero-size canvas */ }
    return origToDataURL.apply(this, args);
  };

  // -- toBlob --
  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function (
    callback: BlobCallback,
    type?: string,
    quality?: number,
  ): void {
    if (!engineEnabled || !effectivePolicy.fingerprint) {
      origToBlob.call(this, callback, type, quality);
      return;
    }
    try {
      if (this.width > 0 && this.height > 0) {
        const tmp = document.createElement("canvas");
        tmp.width = this.width;
        tmp.height = this.height;
        const ctx = tmp.getContext("2d");
        if (ctx) {
          ctx.drawImage(this, 0, 0);
          const img = ctx.getImageData(0, 0, 1, 1);
          img.data[1] = (img.data[1] + noiseSeed) & 0xff;
          ctx.putImageData(img, 0, 0);
          origToBlob.call(tmp, callback, type, quality);
          return;
        }
      }
    } catch { /* tainted or zero-size canvas */ }
    origToBlob.call(this, callback, type, quality);
  };

  // -- getImageData --
  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (
    ...args: Parameters<typeof origGetImageData>
  ): ImageData {
    const imageData = origGetImageData.apply(this, args);
    if (!engineEnabled || !effectivePolicy.fingerprint) return imageData;
    const len = Math.min(imageData.data.length, 16);
    for (let i = 0; i < len; i += 4) {
      imageData.data[i] = (imageData.data[i] + noiseSeed) & 0xff;
    }
    return imageData;
  };

  // -- WebGL renderer/vendor --
  const poisonWebGL = (proto: WebGLRenderingContext | WebGL2RenderingContext) => {
    const orig = proto.getParameter;
    proto.getParameter = function (pname: GLenum): ReturnType<typeof orig> {
      if (!engineEnabled || !effectivePolicy.fingerprint) return orig.call(this, pname);
      const ext = this.getExtension("WEBGL_debug_renderer_info");
      if (ext) {
        if (pname === ext.UNMASKED_VENDOR_WEBGL)   return "Generic Vendor";
        if (pname === ext.UNMASKED_RENDERER_WEBGL) return "Generic Renderer";
      }
      return orig.call(this, pname);
    };
  };

  try { poisonWebGL(WebGLRenderingContext.prototype);  } catch { /* WebGL unavailable  */ }
  try { poisonWebGL(WebGL2RenderingContext.prototype); } catch { /* WebGL2 unavailable */ }
}

/** Override navigator / screen properties with bundle values. */
function spoofNavigatorAndScreen(bundle: FingerprintBundle): void {
  const def = (obj: object, prop: string, value: unknown) => {
    try {
      Object.defineProperty(obj, prop, { get: () => value, configurable: true });
    } catch { /* non-configurable */ }
  };

  def(navigator, "hardwareConcurrency", bundle.hardwareConcurrency);
  def(navigator, "deviceMemory",        bundle.deviceMemory);
  def(navigator, "platform",            bundle.platform);
  def(navigator, "languages",           bundle.languages);
  def(screen, "width",      bundle.screenWidth);
  def(screen, "height",     bundle.screenHeight);
  def(screen, "colorDepth", bundle.colorDepth);
  def(screen, "pixelDepth", bundle.colorDepth);
}

/* ================================================================== */
/*  Module 1 — Interception: addEventListener patching                */
/* ================================================================== */

const trackedSet = new Set<string>(TRACKED_EVENTS);

type AnyListener = EventListenerOrEventListenerObject;
type OrigAEL = typeof EventTarget.prototype.addEventListener;
type OrigREL = typeof EventTarget.prototype.removeEventListener;

const wrapperRegistry = new WeakMap<AnyListener, Map<string, EventListener>>();

function getWrapped(l: AnyListener, t: string): EventListener | undefined {
  return wrapperRegistry.get(l)?.get(t);
}

function setWrapped(l: AnyListener, t: string, w: EventListener): void {
  let inner = wrapperRegistry.get(l);
  if (!inner) { inner = new Map(); wrapperRegistry.set(l, inner); }
  inner.set(t, w);
}

/**
 * Mutate keyboard event timestamps to disrupt inter-keystroke timing analysis.
 * Returns a Proxy so the original event object is never mutated.
 */
function maybeMutateTimestamp(evt: Event): Event {
  if (!effectivePolicy.intercept) return evt;
  if (evt.type !== "keydown" && evt.type !== "keyup") return evt;

  const jitter = randFloat(-intensityConfig.jitterMs, intensityConfig.jitterMs);
  return new Proxy(evt, {
    get(target, prop) {
      if (prop === "timeStamp") return Math.max(0, target.timeStamp + jitter);
      const val = Reflect.get(target, prop);
      return typeof val === "function" ? val.bind(target) : val;
    },
  });
}

function patchAddEventListener(proto: EventTarget): void {
  const origAdd: OrigAEL    = proto.addEventListener;
  const origRemove: OrigREL = proto.removeEventListener;

  proto.addEventListener = function (
    type: string,
    listener: AnyListener | null,
    options?: boolean | AddEventListenerOptions,
  ): void {
    if (!listener || !trackedSet.has(type) || !effectivePolicy.intercept) {
      return origAdd.call(this, type, listener, options);
    }

    let wrapped = getWrapped(listener, type);
    if (!wrapped) {
      wrapped = (evt: Event) => {
        if (!engineEnabled || isSynthetic(evt)) {
          // Pass synthetic events through without processing
          if (typeof listener === "function") listener(evt);
          else listener.handleEvent(evt);
          return;
        }

        pendingIntercepted++;
        trackSuccess("intercept");

        const mutated = maybeMutateTimestamp(evt);
        if (typeof listener === "function") listener(mutated);
        else listener.handleEvent(mutated);
      };
      setWrapped(listener, type, wrapped);
    }

    return origAdd.call(this, type, wrapped, options);
  };

  proto.removeEventListener = function (
    type: string,
    listener: AnyListener | null,
    options?: boolean | EventListenerOptions,
  ): void {
    if (!listener || !trackedSet.has(type)) {
      return origRemove.call(this, type, listener, options);
    }
    const w = getWrapped(listener, type) ?? listener;
    return origRemove.call(this, type, w, options);
  };
}

// Apply patches to the three prototype chains
patchAddEventListener(Window.prototype);
patchAddEventListener(Document.prototype);
patchAddEventListener(Element.prototype);

/* ================================================================== */
/*  Module 2 — Poisoning: behavioral templates + rate limiter         */
/* ================================================================== */

/**
 * Generate synthetic mouse events along a smooth arc toward a randomised
 * offset target.  Uses ease-in-out interpolation + Gaussian jitter so the
 * arc looks more like a real hand movement than a straight line.
 */
function generateMouseArc(base: MouseEvent, count: number): MouseEvent[] {
  const events: MouseEvent[] = [];
  const off     = intensityConfig.mouseOffset;
  const targetX = base.clientX + Math.round(randGaussian(0, off / 2));
  const targetY = base.clientY + Math.round(randGaussian(0, off / 2));

  for (let i = 0; i < count; i++) {
    const t      = (i + 1) / (count + 1);
    // Cubic ease-in-out: accelerate from 0→0.5, decelerate from 0.5→1
    const eased  = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
    const x      = Math.round(base.clientX + (targetX - base.clientX) * eased + randGaussian(0, 2));
    const y      = Math.round(base.clientY + (targetY - base.clientY) * eased + randGaussian(0, 2));
    const evt    = new MouseEvent("mousemove", {
      clientX:   x,
      clientY:   y,
      screenX:   base.screenX + (x - base.clientX),
      screenY:   base.screenY + (y - base.clientY),
      movementX: Math.round(randGaussian(0, 4)),
      movementY: Math.round(randGaussian(0, 4)),
      bubbles:   true,
      cancelable: true,
    });
    markSynthetic(evt);
    events.push(evt);
  }
  return events;
}

function generateSyntheticClick(base: MouseEvent): MouseEvent {
  const off = intensityConfig.clickOffset;
  const evt = new MouseEvent("click", {
    clientX:   base.clientX + Math.round(randGaussian(0, off / 3)),
    clientY:   base.clientY + Math.round(randGaussian(0, off / 3)),
    button:    0,
    bubbles:   true,
    cancelable: true,
  });
  markSynthetic(evt);
  return evt;
}

/**
 * Generate a synthetic keystroke using approximate English letter-frequency
 * distribution (ETAOIN SHRDLU ordering) so the key mix is more realistic
 * than a uniform random selection.
 */
// Letter frequencies derived from ETAOIN SHRDLU — repeated chars approximate real distribution
const KEY_POOL = "eeeeeeeeeeetttttttttaaaaaaaaoooooooiiiiiiiinnnnnnnsssssssrrrrrrrhhhhhhldddccuuummmfffggppwwyyyybbvvkxjqz ";
const DIGIT_POOL = "0123456789";

function generateRealisticKey(type: "keydown" | "keyup"): KeyboardEvent {
  const useDigit = xorshift128plus() < 0.1;
  const pool     = useDigit ? DIGIT_POOL : KEY_POOL;
  const key      = pool[randInt(0, pool.length - 1)];

  let code: string;
  if (key === " ")       code = "Space";
  else if (/\d/.test(key)) code = `Digit${key}`;
  else                   code = `Key${key.toUpperCase()}`;

  const evt = new KeyboardEvent(type, { key, code, bubbles: true, cancelable: true });
  markSynthetic(evt);
  return evt;
}

function generateSyntheticScroll(): Event {
  const evt = new Event("scroll", { bubbles: true, cancelable: false });
  markSynthetic(evt);
  return evt;
}

const syntheticQueue: Event[] = [];
let flushScheduled = false;

function scheduleSyntheticFlush(): void {
  if (flushScheduled) return;
  flushScheduled = true;
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
    try {
      target.dispatchEvent(syntheticQueue.shift()!);
    } catch { /* swallow errors from synthetic dispatch */ }
  }
}

function enqueueSynthetics(evt: Event): void {
  if (!engineEnabled || !effectivePolicy.poison) return;

  // Sensitive-page guardrail — never inject on payment / login pages
  if (sensitiveContext) {
    trackRateLimit("poison");
    return;
  }

  // Token-bucket rate limit — prevents CPU spikes under heavy activity
  if (!consumeToken()) {
    trackRateLimit("poison");
    return;
  }

  if (syntheticQueue.length >= MAX_QUEUE) return;

  const count = randInt(intensityConfig.minSynthetic, intensityConfig.maxSynthetic);

  try {
    switch (evt.type) {
      case "mousemove": {
        const arcs = generateMouseArc(evt as MouseEvent, count);
        for (const e of arcs) syntheticQueue.push(e);
        pendingSynthetic += arcs.length;
        break;
      }
      case "click": {
        for (let i = 0; i < count; i++) {
          syntheticQueue.push(generateSyntheticClick(evt as MouseEvent));
          pendingSynthetic++;
        }
        break;
      }
      case "keydown":
      case "keyup": {
        for (let i = 0; i < count; i++) {
          syntheticQueue.push(generateRealisticKey(evt.type as "keydown" | "keyup"));
          pendingSynthetic++;
        }
        break;
      }
      case "scroll": {
        for (let i = 0; i < count; i++) {
          syntheticQueue.push(generateSyntheticScroll());
          pendingSynthetic++;
        }
        break;
      }
    }
    trackSuccess("poison");
    scheduleSyntheticFlush();
  } catch (err) {
    trackError("poison", err);
  }
}

function attachEventDelegation(): void {
  for (const eventType of TRACKED_EVENTS) {
    document.addEventListener(
      eventType,
      (evt: Event) => {
        if (isSynthetic(evt)) return;
        enqueueSynthetics(evt);
      },
      { capture: true, passive: true },
    );
  }
}

/* ================================================================== */
/*  Module 4 — Sanitization: PII redaction                            */
/* ================================================================== */

const PII_PATTERNS: { pattern: RegExp; replacement: string }[] = [
  { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, replacement: "[email redacted]" },
  { pattern: /(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}/g, replacement: "[phone redacted]" },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: "[SSN redacted]" },
  { pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, replacement: "[card redacted]" },
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: "[IP redacted]" },
  {
    pattern: /\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct)\b/gi,
    replacement: "[address redacted]",
  },
];

function sanitizeText(text: string): { sanitized: string; changed: boolean } {
  let result  = text;
  let changed = false;
  for (const { pattern, replacement } of PII_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(result)) {
      changed = true;
      pattern.lastIndex = 0;
      result  = result.replace(pattern, replacement);
    }
  }
  return { sanitized: result, changed };
}

function attachPromptSanitization(): void {
  document.addEventListener(
    "submit",
    (evt: Event) => {
      if (!engineEnabled || !effectivePolicy.sanitize) return;
      const form = evt.target as HTMLFormElement;
      if (!form) return;

      try {
        const textInputs = form.querySelectorAll<HTMLTextAreaElement | HTMLInputElement>(
          "textarea, input[type='text'], input[type='search']",
        );
        for (const input of textInputs) {
          const { sanitized, changed } = sanitizeText(input.value);
          if (changed) {
            input.value = sanitized;
            pendingSanitized++;
            trackSuccess("sanitize");
            pushActivity("sanitized", "PII redacted from form input");
          }
        }

        const editables = form.querySelectorAll<HTMLElement>("[contenteditable='true']");
        for (const el of editables) {
          const { sanitized, changed } = sanitizeText(el.innerText);
          if (changed) {
            el.innerText = sanitized;
            pendingSanitized++;
            trackSuccess("sanitize");
            pushActivity("sanitized", "PII redacted from contenteditable");
          }
        }
      } catch (err) {
        trackError("sanitize", err);
      }
    },
    { capture: true },
  );

  // Watch for dynamically injected inputs
  const observer = new MutationObserver((mutations) => {
    if (!engineEnabled || !effectivePolicy.sanitize) return;
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node instanceof HTMLElement) attachInputWatcher(node);
      }
    }
  });

  observer.observe(document.documentElement ?? document.body, { childList: true, subtree: true });
}

function attachInputWatcher(root: HTMLElement): void {
  const targets: HTMLElement[] = [
    ...root.querySelectorAll<HTMLElement>("textarea, [contenteditable='true']"),
  ];
  if (root.matches("textarea") || root.getAttribute("contenteditable") === "true") {
    targets.push(root);
  }

  for (const el of targets) {
    const marker = el as unknown as Record<string, unknown>;
    if (marker.__vitiate_watched__) continue;
    marker.__vitiate_watched__ = true;

    el.addEventListener("paste", (evt: Event) => {
      if (!engineEnabled || !effectivePolicy.sanitize) return;
      const clip = (evt as ClipboardEvent).clipboardData?.getData("text/plain");
      if (!clip) return;

      try {
        const { sanitized, changed } = sanitizeText(clip);
        if (changed) {
          evt.preventDefault();
          if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
            const start = el.selectionStart ?? el.value.length;
            const end   = el.selectionEnd   ?? el.value.length;
            el.setRangeText(sanitized, start, end, "end");
          } else {
            const sel = window.getSelection();
            if (sel && sel.rangeCount > 0) {
              const range = sel.getRangeAt(0);
              range.deleteContents();
              range.insertNode(document.createTextNode(sanitized));
              range.collapse(false);
              sel.removeAllRanges();
              sel.addRange(range);
            }
          }
          pendingSanitized++;
          trackSuccess("sanitize");
          pushActivity("sanitized", "PII redacted from paste");
        }
      } catch (err) {
        trackError("sanitize", err);
      }
    });
  }
}

/* ================================================================== */
/*  Metrics flush (includes module counter reports)                   */
/* ================================================================== */

function flushMetrics(): void {
  // Sensitive-page re-check on each flush cycle (handles lazy-loaded forms)
  checkSensitiveContext();

  if (pendingIntercepted > 0) pushActivity("intercepted", `${pendingIntercepted} events intercepted`);
  if (pendingSynthetic   > 0) pushActivity("poisoned",    `${pendingSynthetic} synthetic events injected`);

  if (pendingIntercepted > 0 || pendingSynthetic > 0 || pendingSanitized > 0) {
    chrome.runtime.sendMessage({
      type: "REPORT_METRICS",
      delta: {
        interceptedEvents:       pendingIntercepted,
        syntheticEventsInjected: pendingSynthetic,
        sanitizedInputs:         pendingSanitized,
      },
    } satisfies VitiateMessage).catch(() => {});

    pendingIntercepted = 0;
    pendingSynthetic   = 0;
    pendingSanitized   = 0;
  }

  // Flush per-module counters
  for (const mid of Object.keys(localCounters) as ModuleId[]) {
    const c = localCounters[mid];
    if (c.processed > 0 || c.errors > 0 || c.skippedRateLimit > 0) {
      chrome.runtime.sendMessage({
        type: "REPORT_MODULE_COUNTER",
        module: mid,
        delta: { processed: c.processed, errors: c.errors, skippedRateLimit: c.skippedRateLimit },
      } satisfies VitiateMessage).catch(() => {});
      localCounters[mid] = { ...defaultModuleCounter(), lastActiveMs: c.lastActiveMs };
    }
  }

  flushActivity();
}

/* ================================================================== */
/*  Initialisation                                                     */
/* ================================================================== */

async function init(): Promise<void> {
  try {
    const response = await chrome.runtime.sendMessage({
      type: "GET_SETTINGS",
      domain: location.hostname,
    } satisfies VitiateMessage) as VitiateMessage;

    if (response?.type === "SETTINGS_RESPONSE") {
      engineEnabled     = response.domainEnabled;
      currentIntensity  = response.settings.intensity ?? "medium";
      intensityConfig   = INTENSITY_CONFIGS[currentIntensity];
      effectivePolicy   = response.effectivePolicy ?? effectivePolicy;
    }
  } catch {
    // First run or extension context invalid — use defaults
    engineEnabled = true;
  }

  // Initialise the token bucket with the current intensity budget
  tokenBucket.tokens      = intensityConfig.tokenBucketMax;
  tokenBucket.lastRefillMs = Date.now();

  // Rebuild the fingerprint bundle with a fresh session seed
  fpBundle = buildCoherentFingerprintBundle();

  // Check for sensitive page before applying any modules
  checkSensitiveContext();

  // Apply fingerprint defenses early (before page scripts run)
  applyFingerprintModule();

  // Attach interception and sanitization event hooks
  attachEventDelegation();
  attachPromptSanitization();

  // Periodically flush metrics and counters to the background worker
  setInterval(flushMetrics, METRICS_FLUSH_MS);
}

init();
