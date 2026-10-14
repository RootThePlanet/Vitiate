/**
 * Vitiate — Page-world defenses (October 2026)
 *
 * Runs in the page's MAIN world at document_start. Isolated-world prototype
 * patches do not affect page scripts, so every defense that must be visible
 * to trackers lives here. This file must not touch extension APIs.
 *
 * What still works, and what we deliberately stopped doing:
 *
 * - `isTrusted` cannot be forged. Synthetic clicks, keys, and scrolls are
 *   ignored by current bot managers and can activate real handlers. Poisoning
 *   is limited to low-volume pointer/mouse noise for naive heatmaps.
 * - Listener delays desync callback time from `timeStamp` and break IMEs.
 *   Intercept only jitters timestamps, and only in an order-preserving way.
 * - Random `navigator.platform` / screen / language / "Generic GPU" strings
 *   contradict userAgentData, media queries, and WebGPU. That mismatch is a
 *   stronger signal than the raw value. Those lies are gone.
 * - Fingerprinting moved to OffscreenCanvas, `copyFromChannel`, WebGPU
 *   adapter info, and high-entropy client hints. Those paths are covered.
 *   Worker-created canvases are not — see the README.
 * - Mutating form values corrupted first-party submits. Sanitization now
 *   redacts outbound telemetry payloads only.
 */

import {
  INTENSITY_CONFIGS,
  PAGE_BRIDGE_CHANNEL,
  type ActivityEntry,
  type IntensityConfig,
  type IntensityLevel,
  type ModuleId,
  type ModulePolicy,
  type PageWorldConfig,
  type PageWorldReport,
} from "../shared/types";

if ((globalThis as { __vitiate_page_world__?: boolean }).__vitiate_page_world__) {
  throw new Error("Vitiate page world already installed");
}
(globalThis as { __vitiate_page_world__?: boolean }).__vitiate_page_world__ = true;

/* ================================================================== */
/*  State                                                              */
/* ================================================================== */

const INTERCEPT_EVENTS = new Set([
  "keydown",
  "keyup",
  "beforeinput",
  "pointerdown",
  "click",
  "wheel",
]);

const MAX_QUEUE = 128;
const MAX_ACTIVITY = 20;
const FLUSH_MS = 5_000;
const MAX_FINGERPRINT_PIXELS = 1024 * 1024;
const MAX_AUDIO_SAMPLES = 200_000;
const MAX_REDACT_CHARS = 500_000;

const SENSITIVE_URL_RE =
  /\b(?:bank|payment|paypal|checkout|billing|wallet|finance|credit|transaction|signin|login|auth|stripe)\b/i;

let engineEnabled = true;
let currentIntensity: IntensityLevel = "medium";
let intensityConfig: IntensityConfig = { ...INTENSITY_CONFIGS.medium };
let effectivePolicy: ModulePolicy = {
  intercept: true,
  poison: true,
  fingerprint: true,
  sanitize: true,
};

let pendingIntercepted = 0;
let pendingSynthetic = 0;
let pendingSanitized = 0;
let activityBuffer: ActivityEntry[] = [];
let sensitiveContext = false;
let reportedSensitive = false;

const counterDelta: Record<ModuleId, { processed: number; errors: number; skippedRateLimit: number }> = {
  intercept: { processed: 0, errors: 0, skippedRateLimit: 0 },
  poison: { processed: 0, errors: 0, skippedRateLimit: 0 },
  fingerprint: { processed: 0, errors: 0, skippedRateLimit: 0 },
  sanitize: { processed: 0, errors: 0, skippedRateLimit: 0 },
};
const pendingIncidents: { module: ModuleId; message: string }[] = [];

/* ================================================================== */
/*  PRNG + session-stable fingerprint seed                             */
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

function randGaussian(mean: number, std: number): number {
  const u1 = Math.max(xorshift128plus(), 1e-10);
  const u2 = xorshift128plus();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return mean + z * std;
}

/**
 * Same host + same UTC week => same noise, including same-origin iframes.
 * Cross-site frames differ, so a third-party frame cannot replay the top
 * frame's exact readback. Rotates weekly so the noised hash is not permanent.
 */
function fnv1a(text: string): number {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const fpSeed = fnv1a(`${location.hostname}|${Math.floor(Date.now() / 604_800_000)}`);

/* ================================================================== */
/*  Token bucket                                                       */
/* ================================================================== */

const tokenBucket = { tokens: intensityConfig.tokenBucketMax, lastRefillMs: Date.now() };

function refillTokens(): void {
  const now = Date.now();
  const elapsed = (now - tokenBucket.lastRefillMs) / 1000;
  tokenBucket.tokens = Math.min(
    intensityConfig.tokenBucketMax,
    tokenBucket.tokens + elapsed * intensityConfig.tokenRefillRate,
  );
  tokenBucket.lastRefillMs = now;
  if (typeof requestIdleCallback !== "undefined") {
    requestIdleCallback(() => refillTokens(), { timeout: 1000 });
  } else {
    setTimeout(refillTokens, 1000);
  }
}
refillTokens();

function consumeToken(): boolean {
  if (tokenBucket.tokens >= 1) {
    tokenBucket.tokens -= 1;
    return true;
  }
  return false;
}

/* ================================================================== */
/*  Reporting                                                          */
/* ================================================================== */

function pushActivity(kind: ActivityEntry["kind"], detail: string): void {
  activityBuffer.push({ time: new Date().toISOString(), kind, detail });
  if (activityBuffer.length > MAX_ACTIVITY) activityBuffer.shift();
}

function trackSuccess(module: ModuleId): void {
  counterDelta[module].processed++;
}

function trackError(module: ModuleId, err: unknown): void {
  counterDelta[module].errors++;
  const msg = err instanceof Error ? err.message : String(err);
  pendingIncidents.push({ module, message: msg.slice(0, 120) });
}

function trackRateLimit(module: ModuleId): void {
  counterDelta[module].skippedRateLimit++;
}

function flushReport(): void {
  checkSensitiveContext();
  const report: PageWorldReport = {
    intercepted: pendingIntercepted,
    synthetic: pendingSynthetic,
    sanitized: pendingSanitized,
    activity: activityBuffer.splice(0),
    counters: {},
    incidents: pendingIncidents.splice(0),
  };
  let hasCounters = false;
  for (const id of Object.keys(counterDelta) as ModuleId[]) {
    const c = counterDelta[id];
    if (c.processed || c.errors || c.skippedRateLimit) {
      report.counters[id] = { ...c };
      counterDelta[id] = { processed: 0, errors: 0, skippedRateLimit: 0 };
      hasCounters = true;
    }
  }
  if (
    report.intercepted === 0 &&
    report.synthetic === 0 &&
    report.sanitized === 0 &&
    report.activity.length === 0 &&
    report.incidents.length === 0 &&
    !hasCounters
  ) {
    return;
  }
  pendingIntercepted = 0;
  pendingSynthetic = 0;
  pendingSanitized = 0;
  window.postMessage({ channel: PAGE_BRIDGE_CHANNEL, kind: "report", report }, "*");
}

/* ================================================================== */
/*  Config from the isolated bridge                                    */
/* ================================================================== */

function applyConfig(config: PageWorldConfig): void {
  engineEnabled = config.enabled;
  currentIntensity = config.intensity ?? "medium";
  intensityConfig = { ...INTENSITY_CONFIGS[currentIntensity] ?? INTENSITY_CONFIGS.medium };
  if (typeof config.tokenRefillRate === "number") intensityConfig.tokenRefillRate = config.tokenRefillRate;
  if (typeof config.tokenBucketMax === "number") intensityConfig.tokenBucketMax = config.tokenBucketMax;
  effectivePolicy = { ...effectivePolicy, ...config.policy };
  compileCustomRules(config.customSanitizationRules ?? []);
}

window.addEventListener("message", (ev: MessageEvent) => {
  if (ev.source !== window) return;
  const data = ev.data as { channel?: string; kind?: string; config?: PageWorldConfig } | null;
  if (!data || data.channel !== PAGE_BRIDGE_CHANNEL || data.kind !== "config" || !data.config) return;
  try {
    applyConfig(data.config);
  } catch (err) {
    trackError("intercept", err);
  }
});

/* ================================================================== */
/*  Sensitive-page guard                                               */
/* ================================================================== */

function checkSensitiveContext(): void {
  const was = sensitiveContext;
  let hasSecret = false;
  try {
    hasSecret = document.querySelector(
      'input[type="password"], [autocomplete="one-time-code"], [autocomplete^="cc-"], [autocomplete*="password"]',
    ) !== null;
  } catch { /* DOM not ready */ }
  sensitiveContext =
    SENSITIVE_URL_RE.test(location.hostname) ||
    SENSITIVE_URL_RE.test(location.pathname) ||
    hasSecret;
  if (sensitiveContext && !was && !reportedSensitive) {
    reportedSensitive = true;
    pendingIncidents.push({
      module: "poison",
      message: "Sensitive page — synthetic pointer noise paused",
    });
    pushActivity("error", "Sensitive context — pointer poisoning paused");
  }
}

function isCredentialTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) return false;
  const type = (target.getAttribute("type") || "").toLowerCase();
  const ac = (target.getAttribute("autocomplete") || "").toLowerCase();
  return type === "password" || ac === "one-time-code" || ac.includes("password") || ac.startsWith("cc-");
}

/* ================================================================== */
/*  Module 3 — Fingerprint readbacks                                   */
/* ================================================================== */

let inCanvasHook = false;
let maskedWebGL: { vendor: string; renderer: string } | null = null;

function captureMaskedWebGL(): void {
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl");
    if (!gl) return;
    const vendor = gl.getParameter(gl.VENDOR);
    const renderer = gl.getParameter(gl.RENDERER);
    if (typeof vendor === "string" && typeof renderer === "string") {
      maskedWebGL = { vendor, renderer };
    }
    const lose = gl.getExtension("WEBGL_lose_context");
    lose?.loseContext();
  } catch { /* no WebGL at document_start */ }
}

/** Low-bit flip on a deterministic stride. Not a single corner pixel. */
function noiseBytes(bytes: ArrayLike<number> & { [index: number]: number }, length: number, seed: number): void {
  if (length < 4) return;
  const step = 16 + (seed % 48);
  let state = seed >>> 0;
  for (let i = seed % step; i < length; i += step) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    bytes[i] = (bytes[i] ^ (state & 1)) & 0xff;
  }
}

function noiseFloat32(data: Float32Array, seed: number): void {
  const step = 64 + (seed % 64);
  const amp = ((seed % 7) + 1) * 1e-7;
  for (let i = seed % step; i < data.length; i += step) {
    data[i] += amp;
  }
}

function installCanvasNoise(): void {
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function (...args: Parameters<typeof origToDataURL>): string {
    if (inCanvasHook || !engineEnabled || !effectivePolicy.fingerprint) return origToDataURL.apply(this, args);
    try {
      if (this.width > 0 && this.height > 0 && this.width * this.height <= MAX_FINGERPRINT_PIXELS) {
        const tmp = document.createElement("canvas");
        tmp.width = this.width;
        tmp.height = this.height;
        const ctx = tmp.getContext("2d", { willReadFrequently: true });
        if (ctx) {
          inCanvasHook = true;
          try {
            ctx.drawImage(this, 0, 0);
            const img = ctx.getImageData(0, 0, tmp.width, tmp.height);
            noiseBytes(img.data, img.data.length, fpSeed);
            ctx.putImageData(img, 0, 0);
          } finally {
            inCanvasHook = false;
          }
          return origToDataURL.apply(tmp, args);
        }
      }
    } catch { /* tainted canvas */ }
    return origToDataURL.apply(this, args);
  };

  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function (callback, type?, quality?): void {
    if (inCanvasHook || !engineEnabled || !effectivePolicy.fingerprint) {
      origToBlob.call(this, callback, type, quality);
      return;
    }
    try {
      if (this.width > 0 && this.height > 0 && this.width * this.height <= MAX_FINGERPRINT_PIXELS) {
        const tmp = document.createElement("canvas");
        tmp.width = this.width;
        tmp.height = this.height;
        const ctx = tmp.getContext("2d", { willReadFrequently: true });
        if (ctx) {
          inCanvasHook = true;
          try {
            ctx.drawImage(this, 0, 0);
            const img = ctx.getImageData(0, 0, tmp.width, tmp.height);
            noiseBytes(img.data, img.data.length, fpSeed);
            ctx.putImageData(img, 0, 0);
          } finally {
            inCanvasHook = false;
          }
          origToBlob.call(tmp, callback, type, quality);
          return;
        }
      }
    } catch { /* tainted canvas */ }
    origToBlob.call(this, callback, type, quality);
  };

  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (...args: Parameters<typeof origGetImageData>): ImageData {
    const imageData = origGetImageData.apply(this, args);
    if (inCanvasHook || !engineEnabled || !effectivePolicy.fingerprint) return imageData;
    if (imageData.width * imageData.height > MAX_FINGERPRINT_PIXELS) return imageData;
    noiseBytes(imageData.data, imageData.data.length, fpSeed);
    return imageData;
  };

  if (typeof OffscreenCanvas !== "undefined" && OffscreenCanvas.prototype.convertToBlob) {
    const origConvert = OffscreenCanvas.prototype.convertToBlob;
    OffscreenCanvas.prototype.convertToBlob = function (options?: ImageEncodeOptions): Promise<Blob> {
      if (inCanvasHook || !engineEnabled || !effectivePolicy.fingerprint) return origConvert.call(this, options);
      try {
        if (this.width > 0 && this.height > 0 && this.width * this.height <= MAX_FINGERPRINT_PIXELS) {
          const tmp = new OffscreenCanvas(this.width, this.height);
          const ctx = tmp.getContext("2d");
          if (ctx) {
            inCanvasHook = true;
            try {
              ctx.drawImage(this, 0, 0);
              const img = ctx.getImageData(0, 0, tmp.width, tmp.height);
              noiseBytes(img.data, img.data.length, fpSeed);
              ctx.putImageData(img, 0, 0);
            } finally {
              inCanvasHook = false;
            }
            return origConvert.call(tmp, options);
          }
        }
      } catch { /* webgl-only or tainted */ }
      return origConvert.call(this, options);
    };
  }
}

function installWebGLMask(): void {
  const hook = (proto: WebGLRenderingContext | WebGL2RenderingContext) => {
    const origGet = proto.getParameter;
    const cache = new WeakMap<object, { vendor: number; renderer: number } | null>();
    proto.getParameter = function (pname: GLenum) {
      if (engineEnabled && effectivePolicy.fingerprint) {
        let info = cache.get(this);
        if (info === undefined) {
          const ext = this.getExtension("WEBGL_debug_renderer_info");
          info = ext
            ? { vendor: ext.UNMASKED_VENDOR_WEBGL, renderer: ext.UNMASKED_RENDERER_WEBGL }
            : null;
          cache.set(this, info);
        }
        if (info && pname === info.vendor) return origGet.call(this, this.VENDOR);
        if (info && pname === info.renderer) return origGet.call(this, this.RENDERER);
      }
      return origGet.call(this, pname);
    };

    const origRead = proto.readPixels;
    proto.readPixels = function (this: WebGLRenderingContext | WebGL2RenderingContext, ...args: unknown[]): void {
      (origRead as (...inner: unknown[]) => void).apply(this, args);
      if (!engineEnabled || !effectivePolicy.fingerprint) return;
      const width = Number(args[2] ?? 0);
      const height = Number(args[3] ?? 0);
      const pixels = args[6];
      // Large drawing buffers are apps (maps, games). Fingerprint canvases are small.
      const bufferPixels = this.drawingBufferWidth * this.drawingBufferHeight;
      if (!pixels || width * height <= 0 || bufferPixels <= 0 || bufferPixels > MAX_FINGERPRINT_PIXELS) return;
      if (pixels instanceof Uint8Array || pixels instanceof Uint8ClampedArray) {
        noiseBytes(pixels, pixels.length, fpSeed);
      }
    } as typeof proto.readPixels;
  };

  try { hook(WebGLRenderingContext.prototype); } catch { /* unavailable */ }
  try { hook(WebGL2RenderingContext.prototype); } catch { /* unavailable */ }
}

function installAudioNoise(): void {
  if (typeof AudioBuffer !== "undefined" && AudioBuffer.prototype.getChannelData) {
    const orig = AudioBuffer.prototype.getChannelData;
    AudioBuffer.prototype.getChannelData = function (this: AudioBuffer, channel: number): Float32Array {
      const original = orig.call(this, channel);
      if (!engineEnabled || !effectivePolicy.fingerprint || original.length > MAX_AUDIO_SAMPLES) return original;
      const copy = new Float32Array(original);
      noiseFloat32(copy, fpSeed);
      return copy;
    } as typeof AudioBuffer.prototype.getChannelData;
  }
  if (typeof AudioBuffer !== "undefined" && AudioBuffer.prototype.copyFromChannel) {
    const orig = AudioBuffer.prototype.copyFromChannel;
    AudioBuffer.prototype.copyFromChannel = function (destination, channelNumber, bufferOffset?): void {
      orig.call(this, destination, channelNumber, bufferOffset);
      if (!engineEnabled || !effectivePolicy.fingerprint || destination.length > MAX_AUDIO_SAMPLES) return;
      noiseFloat32(destination, fpSeed);
    };
  }
}

interface LowEntropyUAData {
  brands?: unknown;
  mobile?: unknown;
  platform?: unknown;
  getHighEntropyValues?: (hints: string[]) => Promise<Record<string, unknown>>;
}

function installClientHintReduction(): void {
  const uad = (navigator as Navigator & { userAgentData?: LowEntropyUAData }).userAgentData;
  if (!uad || typeof uad.getHighEntropyValues !== "function") return;
  const orig = uad.getHighEntropyValues.bind(uad);
  const reduced = async (hints: string[]): Promise<Record<string, unknown>> => {
    const full = await orig(hints);
    if (!engineEnabled || !effectivePolicy.fingerprint) return full;
    const out: Record<string, unknown> = {};
    for (const key of ["brands", "mobile", "platform"] as const) {
      if (key in full) out[key] = full[key];
    }
    return out;
  };
  try {
    Object.defineProperty(uad, "getHighEntropyValues", { value: reduced, configurable: true });
  } catch { /* non-configurable */ }
}

function installWebGPUMask(): void {
  const gpu = navigator.gpu;
  if (!gpu || typeof gpu.requestAdapter !== "function") return;
  const orig = gpu.requestAdapter.bind(gpu);
  const maskInfo = (info: GPUAdapterInfo): GPUAdapterInfo => new Proxy(info, {
    get(target, prop, recv) {
      if (prop === "vendor") return maskedWebGL?.vendor ?? "";
      if (prop === "architecture" || prop === "device") return "";
      if (prop === "description") return maskedWebGL?.renderer ?? "";
      const value = Reflect.get(target, prop, recv);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

  gpu.requestAdapter = async function (options?: GPURequestAdapterOptions) {
    const adapter = await orig(options);
    if (!adapter || !engineEnabled || !effectivePolicy.fingerprint) return adapter;
    return new Proxy(adapter, {
      get(target, prop, recv) {
        if (prop === "info" && target.info) return maskInfo(target.info);
        const legacy = target as GPUAdapter & {
          requestAdapterInfo?: (...args: unknown[]) => Promise<GPUAdapterInfo>;
        };
        if (prop === "requestAdapterInfo" && typeof legacy.requestAdapterInfo === "function") {
          const requestInfo = legacy.requestAdapterInfo.bind(target);
          return async (...args: unknown[]) => maskInfo(await requestInfo(...args));
        }
        const value = Reflect.get(target, prop, recv);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  };
}

function applyFingerprintModule(): void {
  if (!effectivePolicy.fingerprint) return;
  try {
    captureMaskedWebGL();
    installCanvasNoise();
    installWebGLMask();
    installAudioNoise();
    installClientHintReduction();
    installWebGPUMask();
    trackSuccess("fingerprint");
  } catch (err) {
    trackError("fingerprint", err);
  }
}

/* ================================================================== */
/*  Module 1 — Intercept: order-preserving timestamp jitter            */
/* ================================================================== */

let lastStampOut = 0;

function distortStamp(ts: number): number {
  const noise = randFloat(-intensityConfig.jitterMs, intensityConfig.jitterMs);
  let out = Math.max(0, ts + noise);
  if (out < lastStampOut) out = lastStampOut;
  lastStampOut = out;
  return out;
}

function jitterEvent(evt: Event): Event {
  if (!effectivePolicy.intercept || isCredentialTarget(evt.target)) return evt;
  const stamped = distortStamp(evt.timeStamp);
  return new Proxy(evt, {
    get(target, prop) {
      if (prop === "timeStamp") return stamped;
      const val = Reflect.get(target, prop);
      return typeof val === "function" ? val.bind(target) : val;
    },
  });
}

function patchAddEventListener(): void {
  const origAdd = EventTarget.prototype.addEventListener;
  const origRemove = EventTarget.prototype.removeEventListener;
  const registry = new WeakMap<object, Map<string, EventListener>>();

  EventTarget.prototype.addEventListener = function (type, listener, options) {
    if (!listener || !INTERCEPT_EVENTS.has(type)) {
      return origAdd.call(this, type, listener, options);
    }
    let wrapped = registry.get(listener)?.get(type);
    if (!wrapped) {
      wrapped = (evt: Event) => {
        const deliver = (event: Event) => {
          if (typeof listener === "function") listener.call(this, event);
          else listener.handleEvent(event);
        };
        if (!engineEnabled || !effectivePolicy.intercept || isCredentialTarget(evt.target)) {
          deliver(evt);
          return;
        }
        pendingIntercepted++;
        trackSuccess("intercept");
        deliver(jitterEvent(evt));
      };
      let inner = registry.get(listener);
      if (!inner) {
        inner = new Map();
        registry.set(listener, inner);
      }
      inner.set(type, wrapped);
    }
    return origAdd.call(this, type, wrapped, options);
  };

  EventTarget.prototype.removeEventListener = function (type, listener, options) {
    const wrapped = listener ? registry.get(listener)?.get(type) : undefined;
    return origRemove.call(this, type, wrapped ?? listener, options);
  };
}

/* ================================================================== */
/*  Module 2 — Poison: untrusted pointer noise only                    */
/* ================================================================== */

const syntheticEvents = new WeakSet<Event>();

function markSynthetic(evt: Event): void {
  syntheticEvents.add(evt);
}

function buildPointerNoise(base: MouseEvent, count: number): Event[] {
  const events: Event[] = [];
  const off = intensityConfig.mouseOffset;
  for (let i = 0; i < count; i++) {
    const x = Math.round(base.clientX + randGaussian(0, Math.max(4, off / 4)));
    const y = Math.round(base.clientY + randGaussian(0, Math.max(4, off / 4)));
    const dx = x - base.clientX;
    const dy = y - base.clientY;
    const common = {
      clientX: x,
      clientY: y,
      screenX: base.screenX + dx,
      screenY: base.screenY + dy,
      movementX: dx,
      movementY: dy,
      bubbles: true,
      cancelable: true,
      view: window,
    };
    const pointer = new PointerEvent("pointermove", {
      ...common,
      pointerId: base instanceof PointerEvent ? base.pointerId : 1,
      pointerType: base instanceof PointerEvent ? base.pointerType : "mouse",
      isPrimary: true,
    });
    const mouse = new MouseEvent("mousemove", common);
    markSynthetic(pointer);
    markSynthetic(mouse);
    events.push(pointer, mouse);
  }
  return events;
}

const syntheticQueue: Event[] = [];
const syntheticTargets = new WeakMap<Event, Node>();
let flushScheduled = false;

function flushSyntheticQueue(): void {
  flushScheduled = false;
  const fallback = document.documentElement ?? document.body;
  while (syntheticQueue.length > 0) {
    const next = syntheticQueue.shift();
    if (!next) break;
    const target = syntheticTargets.get(next) ?? fallback;
    if (!target) continue;
    try {
      target.dispatchEvent(next);
    } catch { /* page listener threw */ }
  }
}

function scheduleSyntheticFlush(): void {
  if (flushScheduled || syntheticQueue.length === 0) return;
  flushScheduled = true;
  if (typeof requestIdleCallback !== "undefined") requestIdleCallback(flushSyntheticQueue, { timeout: 50 });
  else setTimeout(flushSyntheticQueue, 0);
}

function enqueuePointerNoise(evt: Event): void {
  if (!engineEnabled || !effectivePolicy.poison || syntheticEvents.has(evt)) return;
  if (sensitiveContext || isCredentialTarget(evt.target)) {
    trackRateLimit("poison");
    return;
  }
  if (!consumeToken()) {
    trackRateLimit("poison");
    return;
  }
  if (syntheticQueue.length >= MAX_QUEUE) return;
  try {
    const count = randInt(intensityConfig.minSynthetic, intensityConfig.maxSynthetic);
    const noise = buildPointerNoise(evt as MouseEvent, count);
    const target = evt.target instanceof Node ? evt.target : undefined;
    for (const item of noise) {
      if (target) syntheticTargets.set(item, target);
      syntheticQueue.push(item);
    }
    pendingSynthetic += noise.length;
    trackSuccess("poison");
    scheduleSyntheticFlush();
  } catch (err) {
    trackError("poison", err);
  }
}

function attachPoisonListener(): void {
  const type = typeof PointerEvent !== "undefined" ? "pointermove" : "mousemove";
  document.addEventListener(type, enqueuePointerNoise, { capture: true, passive: true });
}

/* ================================================================== */
/*  Module 4 — Sanitize telemetry payloads                             */
/* ================================================================== */

/**
 * Collector hosts. Keep aligned with public/rules.json.
 * Product dashboards (analytics.google.com, app.mixpanel.com, …) are not listed.
 */
const TRACKER_HOST = [
  /(^|\.)google-analytics\.com$/i,
  /(^|\.)mxpnl\.com$/i,
  /(^|\.)mixpanel\.com$/i,
  /(^|\.)amplitude\.com$/i,
  /(^|\.)segment\.io$/i,
  /(^|\.)segment\.com$/i,
  /(^|\.)heapanalytics\.com$/i,
  /(^|\.)heap-api\.com$/i,
  /(^|\.)fullstory\.com$/i,
  /(^|\.)hotjar\.com$/i,
  /(^|\.)hotjar\.io$/i,
  /(^|\.)clarity\.ms$/i,
  /(^|\.)mouseflow\.com$/i,
  /(^|\.)contentsquare\.net$/i,
  /(^|\.)luckyorange\.com$/i,
  /(^|\.)quantummetric\.com$/i,
  /(^|\.)logrocket\.io$/i,
  /(^|\.)logrocket\.com$/i,
  /(^|\.)lr-ingest\.io$/i,
  /(^|\.)cloudflareinsights\.com$/i,
  /(^|\.)nr-data\.net$/i,
  /(^|\.)bat\.bing\.com$/i,
  /(^|\.)doubleclick\.net$/i,
  /browser-intake[a-z0-9.-]*\.datadoghq\.com$/i,
];

const FIRST_PARTY_COLLECTOR = [
  /\/(?:g|j|r)\/collect\/?$/i,
  /\/_\/collect\/?$/i,
  /\/cdn-cgi\/(?:rum|beacon)\b/i,
  /\/(?:matomo|piwik)\.php$/i,
];

let customRules: RegExp[] = [];

function compileCustomRules(rules: string[]): void {
  customRules = [];
  for (const rule of rules) {
    if (!rule || rule.length > 200) continue;
    // Reject obvious nested-quantifier patterns. Not a full ReDoS prover.
    if (/(\([^)]*[+*][^)]*\)){2,}/.test(rule)) continue;
    try {
      customRules.push(new RegExp(rule, "g"));
    } catch { /* invalid user regex */ }
  }
}

function hostIsTracker(hostname: string): boolean {
  return TRACKER_HOST.some((re) => re.test(hostname));
}

/** Hosts that also serve a product UI. Redact collectors only, never the dashboard. */
const APP_HOST_COLLECTORS: { host: RegExp; collector: RegExp }[] = [
  { host: /(^|\.)mixpanel\.com$/i, collector: /^(api|api-js|decide|cdn)\./i },
  { host: /(^|\.)amplitude\.com$/i, collector: /^(api2?|cdn|sr-client-cfg)\./i },
  { host: /(^|\.)segment\.com$/i, collector: /^cdn\./i },
  { host: /(^|\.)fullstory\.com$/i, collector: /^(rs|edge)\./i },
  { host: /(^|\.)hotjar\.com$/i, collector: /^(static|script|in|vars)\./i },
  { host: /(^|\.)doubleclick\.net$/i, collector: /^stats\.g\./i },
  { host: /(^|\.)heapanalytics\.com$/i, collector: /^cdn\./i },
  { host: /(^|\.)mouseflow\.com$/i, collector: /^(cdn|gtm)\./i },
  { host: /(^|\.)luckyorange\.com$/i, collector: /^(cdn|w1|settings|upload)\./i },
  { host: /(^|\.)quantummetric\.com$/i, collector: /^(cdn|rl)\./i },
  { host: /(^|\.)contentsquare\.net$/i, collector: /^(t|c)\./i },
  { host: /(^|\.)logrocket\.com$/i, collector: /^(cdn|r)\./i },
];

function isNarrowTracker(url: URL): boolean {
  const host = url.hostname;
  for (const entry of APP_HOST_COLLECTORS) {
    if (entry.host.test(host)) return entry.collector.test(host);
  }
  return true;
}

function isTelemetryUrl(raw: string): boolean {
  let url: URL;
  try {
    url = new URL(raw, location.href);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  if (hostIsTracker(url.hostname) && isNarrowTracker(url)) return true;
  if (/(^|\.)facebook\.com$/i.test(url.hostname) && /\/tr\/?$/.test(url.pathname)) return true;
  if (/(^|\.)facebook\.net$/i.test(url.hostname) && /fbevents\.js/i.test(url.pathname)) return true;
  if (/(^|\.)googletagmanager\.com$/i.test(url.hostname) && /\/gtag\//.test(url.pathname)) return true;
  if (url.origin !== location.origin) return false;
  if (FIRST_PARTY_COLLECTOR.some((re) => re.test(url.pathname))) return true;
  return /\/collect\/?$/i.test(url.pathname) && /(?:^|[?&])tid=(?:G|UA)-/i.test(url.search);
}

function passesLuhn(digits: string): boolean {
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    const c = digits.charCodeAt(i);
    if (c < 48 || c > 57) return false;
    let n = c - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function redactText(text: string): { text: string; changed: boolean } {
  if (!text || text.length > MAX_REDACT_CHARS) return { text, changed: false };
  let result = text;
  let changed = false;
  const apply = (next: string) => {
    if (next !== result) {
      changed = true;
      result = next;
    }
  };

  apply(result.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[email redacted]"));
  apply(result.replace(
    /\b(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{3}[\s.-])\d{3}[\s.-]\d{4}\b/g,
    "[phone redacted]",
  ));
  apply(result.replace(/\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, "[SSN redacted]"));
  apply(result.replace(/\b\d[\d -]{11,22}\d\b/g, (match) => {
    const digits = match.replace(/\D/g, "");
    return passesLuhn(digits) ? "[card redacted]" : match;
  }));
  apply(result.replace(
    /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    "[IP redacted]",
  ));
  apply(result.replace(
    /\b\d{1,5}\s+\w+\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct)\b/gi,
    "[address redacted]",
  ));
  for (const pattern of customRules) {
    pattern.lastIndex = 0;
    apply(result.replace(pattern, "[custom redacted]"));
  }
  return { text: result, changed };
}

function noteSanitized(detail: string): void {
  pendingSanitized++;
  trackSuccess("sanitize");
  pushActivity("sanitized", detail);
}

function installNetworkRedaction(): void {
  const origFetch = window.fetch.bind(window);
  window.fetch = function (input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    if (!engineEnabled || !effectivePolicy.sanitize) return origFetch(input, init);
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!isTelemetryUrl(raw)) return origFetch(input, init);
    return redactFetch(origFetch, input, init, raw);
  };

  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  const xhrUrls = new WeakMap<XMLHttpRequest, string>();
  XMLHttpRequest.prototype.open = function (
    method: string,
    url: string | URL,
    async?: boolean,
    username?: string | null,
    password?: string | null,
  ): void {
    try { xhrUrls.set(this, String(url)); } catch { /* ignore */ }
    return origOpen.call(this, method, url, async ?? true, username, password);
  };
  XMLHttpRequest.prototype.send = function (body?: Document | XMLHttpRequestBodyInit | null): void {
    const url = xhrUrls.get(this) ?? "";
    if (!engineEnabled || !effectivePolicy.sanitize || !isTelemetryUrl(url)) {
      origSend.call(this, body);
      return;
    }
    try {
      const redactedUrl = redactText(url);
      if (redactedUrl.changed) noteSanitized("PII redacted from telemetry URL");
      if (typeof body === "string" || body instanceof URLSearchParams) {
        const redacted = redactText(String(body));
        if (redacted.changed) noteSanitized("PII redacted from telemetry payload");
        origSend.call(this, redacted.text);
        return;
      }
      if (body instanceof FormData) {
        const copy = new FormData();
        let changed = false;
        for (const [key, value] of body.entries()) {
          if (typeof value === "string") {
            const redacted = redactText(value);
            if (redacted.changed) changed = true;
            copy.append(key, redacted.text);
          } else {
            copy.append(key, value);
          }
        }
        if (changed) noteSanitized("PII redacted from telemetry form payload");
        origSend.call(this, changed ? copy : body);
        return;
      }
    } catch (err) {
      trackError("sanitize", err);
    }
    origSend.call(this, body);
  };

  if (typeof navigator.sendBeacon === "function") {
    const origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function (url: string | URL, data?: BodyInit | null): boolean {
      const raw = String(url);
      if (!engineEnabled || !effectivePolicy.sanitize || !isTelemetryUrl(raw)) return origBeacon(url, data);
      try {
        const redactedUrl = redactText(raw);
        let payload = data;
        let changed = redactedUrl.changed;
        if (typeof data === "string" || data instanceof URLSearchParams) {
          const redacted = redactText(String(data));
          payload = redacted.text;
          changed = changed || redacted.changed;
        }
        if (changed) noteSanitized("PII redacted from beacon payload");
        return origBeacon(redactedUrl.text, payload);
      } catch (err) {
        trackError("sanitize", err);
        return origBeacon(url, data);
      }
    };
  }
}

async function redactFetch(
  origFetch: typeof fetch,
  input: RequestInfo | URL,
  init: RequestInit | undefined,
  raw: string,
): Promise<Response> {
  try {
    const redactedUrl = redactText(raw);
    let changed = redactedUrl.changed;
    let body = init?.body;
    if (typeof body === "string" || body instanceof URLSearchParams) {
      const redacted = redactText(String(body));
      if (redacted.changed) {
        changed = true;
        body = redacted.text;
      }
    } else if (typeof Request !== "undefined" && input instanceof Request && init?.body === undefined) {
      const text = await input.clone().text();
      const redacted = redactText(text);
      if (redacted.changed) {
        changed = true;
        body = redacted.text;
      }
    }
    if (!changed) return origFetch(input, init);
    noteSanitized("PII redacted from telemetry request");
    if (typeof input === "string" || input instanceof URL) {
      return origFetch(redactedUrl.changed ? redactedUrl.text : input, body === init?.body ? init : { ...init, body });
    }
    const req = input;
    return origFetch(redactedUrl.text, {
      method: init?.method ?? req.method,
      headers: init?.headers ?? req.headers,
      body,
      credentials: init?.credentials ?? req.credentials,
      cache: init?.cache,
      redirect: init?.redirect,
      referrer: init?.referrer,
      integrity: init?.integrity,
      keepalive: init?.keepalive ?? req.keepalive,
      signal: init?.signal ?? req.signal,
      mode: init?.mode ?? req.mode,
    });
  } catch (err) {
    trackError("sanitize", err);
    return origFetch(input, init);
  }
}

/* ================================================================== */
/*  Install immediately, then refine when config arrives               */
/* ================================================================== */

applyFingerprintModule();
patchAddEventListener();
attachPoisonListener();
installNetworkRedaction();
checkSensitiveContext();
setInterval(flushReport, FLUSH_MS);
document.addEventListener("DOMContentLoaded", checkSensitiveContext, { once: true });
