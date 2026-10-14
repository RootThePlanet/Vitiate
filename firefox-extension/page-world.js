(function () {
const SCHEMA_VERSION = 2;
const INTENSITY_CONFIGS = {
  low: { minSynthetic: 1, maxSynthetic: 1, jitterMs: 4, mouseOffset: 24, clickOffset: 8, tokenRefillRate: 5, tokenBucketMax: 30 },
  medium: { minSynthetic: 1, maxSynthetic: 2, jitterMs: 12, mouseOffset: 48, clickOffset: 16, tokenRefillRate: 15, tokenBucketMax: 60 },
  high: { minSynthetic: 1, maxSynthetic: 3, jitterMs: 24, mouseOffset: 80, clickOffset: 24, tokenRefillRate: 30, tokenBucketMax: 100 },
  paranoid: { minSynthetic: 2, maxSynthetic: 4, jitterMs: 40, mouseOffset: 120, clickOffset: 36, tokenRefillRate: 50, tokenBucketMax: 150 }
};
const RISK_TIER_PRESETS = {
  low: { intercept: true, poison: false, fingerprint: true, sanitize: true },
  medium: { intercept: true, poison: true, fingerprint: true, sanitize: true },
  high: { intercept: true, poison: true, fingerprint: true, sanitize: true },
  paranoid: { intercept: true, poison: true, fingerprint: true, sanitize: true }
};
function defaultModulePolicy() {
  return { intercept: true, poison: true, fingerprint: true, sanitize: true };
}
function defaultModuleCounter() {
  return { processed: 0, errors: 0, skippedRateLimit: 0, lastActiveMs: 0 };
}
function defaultSettings() {
  return {
    schemaVersion: SCHEMA_VERSION,
    enabled: true,
    domainOverrides: {},
    intensity: "medium",
    modulePolicy: defaultModulePolicy(),
    domainModulePolicy: {},
    customSanitizationRules: []
  };
}
function defaultMetrics() {
  return {
    interceptedEvents: 0,
    syntheticEventsInjected: 0,
    sanitizedInputs: 0,
    timeline: {}
  };
}
function defaultLifetimeMetrics() {
  return {
    interceptedEvents: 0,
    syntheticEventsInjected: 0,
    sanitizedInputs: 0
  };
}
function migrateSettings(raw) {
  const defaults = defaultSettings();
  const version = raw.schemaVersion ?? 1;
  if (version < 2) {
    const intensity = raw.intensity ?? "medium";
    return {
      ...defaults,
      enabled: raw.enabled ?? defaults.enabled,
      domainOverrides: raw.domainOverrides ?? defaults.domainOverrides,
      intensity,
      modulePolicy: { ...RISK_TIER_PRESETS[intensity] }
    };
  }
  return { ...defaults, ...raw };
}
function getPolicyReason(settings, domain) {
  if (!settings.enabled) return "global-disabled";
  if (domain && domain in settings.domainOverrides) {
    return settings.domainOverrides[domain] ? "domain-enabled" : "domain-disabled";
  }
  return "default-enabled";
}
function getEffectiveModulePolicy(settings, domain) {
  const base = { ...settings.modulePolicy };
  if (domain && settings.domainModulePolicy[domain]) {
    return { ...base, ...settings.domainModulePolicy[domain] };
  }
  return base;
}
function isDomainEnabled(settings, domain) {
  if (!settings.enabled) return false;
  if (!domain) return settings.enabled;
  if (domain in settings.domainOverrides) return settings.domainOverrides[domain];
  return true;
}
function formatCompactNumber(n) {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return n.toString();
}
const PAGE_BRIDGE_CHANNEL = "vitiate-bridge-v3";




if (globalThis.__vitiate_page_world__) {
  throw new Error("Vitiate page world already installed");
}
globalThis.__vitiate_page_world__ = true;
const INTERCEPT_EVENTS = /* @__PURE__ */ new Set([
  "keydown",
  "keyup",
  "beforeinput",
  "pointerdown",
  "click",
  "wheel"
]);
const MAX_QUEUE = 128;
const MAX_ACTIVITY = 20;
const FLUSH_MS = 5e3;
const MAX_FINGERPRINT_PIXELS = 1024 * 1024;
const MAX_AUDIO_SAMPLES = 2e5;
const MAX_REDACT_CHARS = 5e5;
const SENSITIVE_URL_RE = /\b(?:bank|payment|paypal|checkout|billing|wallet|finance|credit|transaction|signin|login|auth|stripe)\b/i;
let engineEnabled = true;
let currentIntensity = "medium";
let intensityConfig = { ...INTENSITY_CONFIGS.medium };
let effectivePolicy = {
  intercept: true,
  poison: true,
  fingerprint: true,
  sanitize: true
};
let pendingIntercepted = 0;
let pendingSynthetic = 0;
let pendingSanitized = 0;
let activityBuffer = [];
let sensitiveContext = false;
let reportedSensitive = false;
const counterDelta = {
  intercept: { processed: 0, errors: 0, skippedRateLimit: 0 },
  poison: { processed: 0, errors: 0, skippedRateLimit: 0 },
  fingerprint: { processed: 0, errors: 0, skippedRateLimit: 0 },
  sanitize: { processed: 0, errors: 0, skippedRateLimit: 0 }
};
const pendingIncidents = [];
let _s0 = Math.random() * 4294967295 >>> 0;
let _s1 = Math.random() * 4294967295 >>> 0;
function xorshift128plus() {
  let s1 = _s0;
  const s0 = _s1;
  _s0 = s0;
  s1 ^= s1 << 23;
  s1 ^= s1 >>> 17;
  s1 ^= s0;
  s1 ^= s0 >>> 26;
  _s1 = s1;
  return (_s0 + _s1 >>> 0) / 4294967296;
}
function randInt(min, max) {
  return min + Math.floor(xorshift128plus() * (max - min + 1));
}
function randFloat(min, max) {
  return min + xorshift128plus() * (max - min);
}
function randGaussian(mean, std) {
  const u1 = Math.max(xorshift128plus(), 1e-10);
  const u2 = xorshift128plus();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return mean + z * std;
}
function fnv1a(text) {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}
const fpSeed = fnv1a(`${location.hostname}|${Math.floor(Date.now() / 6048e5)}`);
const tokenBucket = { tokens: intensityConfig.tokenBucketMax, lastRefillMs: Date.now() };
function refillTokens() {
  const now = Date.now();
  const elapsed = (now - tokenBucket.lastRefillMs) / 1e3;
  tokenBucket.tokens = Math.min(
    intensityConfig.tokenBucketMax,
    tokenBucket.tokens + elapsed * intensityConfig.tokenRefillRate
  );
  tokenBucket.lastRefillMs = now;
  if (typeof requestIdleCallback !== "undefined") {
    requestIdleCallback(() => refillTokens(), { timeout: 1e3 });
  } else {
    setTimeout(refillTokens, 1e3);
  }
}
refillTokens();
function consumeToken() {
  if (tokenBucket.tokens >= 1) {
    tokenBucket.tokens -= 1;
    return true;
  }
  return false;
}
function pushActivity(kind, detail) {
  activityBuffer.push({ time: (/* @__PURE__ */ new Date()).toISOString(), kind, detail });
  if (activityBuffer.length > MAX_ACTIVITY) activityBuffer.shift();
}
function trackSuccess(module) {
  counterDelta[module].processed++;
}
function trackError(module, err) {
  counterDelta[module].errors++;
  const msg = err instanceof Error ? err.message : String(err);
  pendingIncidents.push({ module, message: msg.slice(0, 120) });
}
function trackRateLimit(module) {
  counterDelta[module].skippedRateLimit++;
}
function flushReport() {
  checkSensitiveContext();
  const report = {
    intercepted: pendingIntercepted,
    synthetic: pendingSynthetic,
    sanitized: pendingSanitized,
    activity: activityBuffer.splice(0),
    counters: {},
    incidents: pendingIncidents.splice(0)
  };
  let hasCounters = false;
  for (const id of Object.keys(counterDelta)) {
    const c = counterDelta[id];
    if (c.processed || c.errors || c.skippedRateLimit) {
      report.counters[id] = { ...c };
      counterDelta[id] = { processed: 0, errors: 0, skippedRateLimit: 0 };
      hasCounters = true;
    }
  }
  if (report.intercepted === 0 && report.synthetic === 0 && report.sanitized === 0 && report.activity.length === 0 && report.incidents.length === 0 && !hasCounters) {
    return;
  }
  pendingIntercepted = 0;
  pendingSynthetic = 0;
  pendingSanitized = 0;
  window.postMessage({ channel: PAGE_BRIDGE_CHANNEL, kind: "report", report }, "*");
}
function applyConfig(config) {
  engineEnabled = config.enabled;
  currentIntensity = config.intensity ?? "medium";
  intensityConfig = { ...INTENSITY_CONFIGS[currentIntensity] ?? INTENSITY_CONFIGS.medium };
  if (typeof config.tokenRefillRate === "number") intensityConfig.tokenRefillRate = config.tokenRefillRate;
  if (typeof config.tokenBucketMax === "number") intensityConfig.tokenBucketMax = config.tokenBucketMax;
  effectivePolicy = { ...effectivePolicy, ...config.policy };
  compileCustomRules(config.customSanitizationRules ?? []);
}
window.addEventListener("message", (ev) => {
  if (ev.source !== window) return;
  const data = ev.data;
  if (!data || data.channel !== PAGE_BRIDGE_CHANNEL || data.kind !== "config" || !data.config) return;
  try {
    applyConfig(data.config);
  } catch (err) {
    trackError("intercept", err);
  }
});
function checkSensitiveContext() {
  const was = sensitiveContext;
  let hasSecret = false;
  try {
    hasSecret = document.querySelector(
      'input[type="password"], [autocomplete="one-time-code"], [autocomplete^="cc-"], [autocomplete*="password"]'
    ) !== null;
  } catch {
  }
  sensitiveContext = SENSITIVE_URL_RE.test(location.hostname) || SENSITIVE_URL_RE.test(location.pathname) || hasSecret;
  if (sensitiveContext && !was && !reportedSensitive) {
    reportedSensitive = true;
    pendingIncidents.push({
      module: "poison",
      message: "Sensitive page — synthetic pointer noise paused"
    });
    pushActivity("error", "Sensitive context — pointer poisoning paused");
  }
}
function isCredentialTarget(target) {
  if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) return false;
  const type = (target.getAttribute("type") || "").toLowerCase();
  const ac = (target.getAttribute("autocomplete") || "").toLowerCase();
  return type === "password" || ac === "one-time-code" || ac.includes("password") || ac.startsWith("cc-");
}
let inCanvasHook = false;
let maskedWebGL = null;
function captureMaskedWebGL() {
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
  } catch {
  }
}
function noiseBytes(bytes, length, seed) {
  if (length < 4) return;
  const step = 16 + seed % 48;
  let state = seed >>> 0;
  for (let i = seed % step; i < length; i += step) {
    state = Math.imul(state, 1664525) + 1013904223 >>> 0;
    bytes[i] = (bytes[i] ^ state & 1) & 255;
  }
}
function noiseFloat32(data, seed) {
  const step = 64 + seed % 64;
  const amp = (seed % 7 + 1) * 1e-7;
  for (let i = seed % step; i < data.length; i += step) {
    data[i] += amp;
  }
}
function installCanvasNoise() {
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(...args) {
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
    } catch {
    }
    return origToDataURL.apply(this, args);
  };
  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
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
    } catch {
    }
    origToBlob.call(this, callback, type, quality);
  };
  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function(...args) {
    const imageData = origGetImageData.apply(this, args);
    if (inCanvasHook || !engineEnabled || !effectivePolicy.fingerprint) return imageData;
    if (imageData.width * imageData.height > MAX_FINGERPRINT_PIXELS) return imageData;
    noiseBytes(imageData.data, imageData.data.length, fpSeed);
    return imageData;
  };
  if (typeof OffscreenCanvas !== "undefined" && OffscreenCanvas.prototype.convertToBlob) {
    const origConvert = OffscreenCanvas.prototype.convertToBlob;
    OffscreenCanvas.prototype.convertToBlob = function(options) {
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
      } catch {
      }
      return origConvert.call(this, options);
    };
  }
}
function installWebGLMask() {
  const hook = (proto) => {
    const origGet = proto.getParameter;
    const cache = /* @__PURE__ */ new WeakMap();
    proto.getParameter = function(pname) {
      if (engineEnabled && effectivePolicy.fingerprint) {
        let info = cache.get(this);
        if (info === void 0) {
          const ext = this.getExtension("WEBGL_debug_renderer_info");
          info = ext ? { vendor: ext.UNMASKED_VENDOR_WEBGL, renderer: ext.UNMASKED_RENDERER_WEBGL } : null;
          cache.set(this, info);
        }
        if (info && pname === info.vendor) return origGet.call(this, this.VENDOR);
        if (info && pname === info.renderer) return origGet.call(this, this.RENDERER);
      }
      return origGet.call(this, pname);
    };
    const origRead = proto.readPixels;
    proto.readPixels = function(...args) {
      origRead.apply(this, args);
      if (!engineEnabled || !effectivePolicy.fingerprint) return;
      const width = Number(args[2] ?? 0);
      const height = Number(args[3] ?? 0);
      const pixels = args[6];
      const bufferPixels = this.drawingBufferWidth * this.drawingBufferHeight;
      if (!pixels || width * height <= 0 || bufferPixels <= 0 || bufferPixels > MAX_FINGERPRINT_PIXELS) return;
      if (pixels instanceof Uint8Array || pixels instanceof Uint8ClampedArray) {
        noiseBytes(pixels, pixels.length, fpSeed);
      }
    };
  };
  try {
    hook(WebGLRenderingContext.prototype);
  } catch {
  }
  try {
    hook(WebGL2RenderingContext.prototype);
  } catch {
  }
}
function installAudioNoise() {
  if (typeof AudioBuffer !== "undefined" && AudioBuffer.prototype.getChannelData) {
    const orig = AudioBuffer.prototype.getChannelData;
    AudioBuffer.prototype.getChannelData = function(channel) {
      const original = orig.call(this, channel);
      if (!engineEnabled || !effectivePolicy.fingerprint || original.length > MAX_AUDIO_SAMPLES) return original;
      const copy = new Float32Array(original);
      noiseFloat32(copy, fpSeed);
      return copy;
    };
  }
  if (typeof AudioBuffer !== "undefined" && AudioBuffer.prototype.copyFromChannel) {
    const orig = AudioBuffer.prototype.copyFromChannel;
    AudioBuffer.prototype.copyFromChannel = function(destination, channelNumber, bufferOffset) {
      orig.call(this, destination, channelNumber, bufferOffset);
      if (!engineEnabled || !effectivePolicy.fingerprint || destination.length > MAX_AUDIO_SAMPLES) return;
      noiseFloat32(destination, fpSeed);
    };
  }
}
function installClientHintReduction() {
  const uad = navigator.userAgentData;
  if (!uad || typeof uad.getHighEntropyValues !== "function") return;
  const orig = uad.getHighEntropyValues.bind(uad);
  const reduced = async (hints) => {
    const full = await orig(hints);
    if (!engineEnabled || !effectivePolicy.fingerprint) return full;
    const out = {};
    for (const key of ["brands", "mobile", "platform"]) {
      if (key in full) out[key] = full[key];
    }
    return out;
  };
  try {
    Object.defineProperty(uad, "getHighEntropyValues", { value: reduced, configurable: true });
  } catch {
  }
}
function installWebGPUMask() {
  const gpu = navigator.gpu;
  if (!gpu || typeof gpu.requestAdapter !== "function") return;
  const orig = gpu.requestAdapter.bind(gpu);
  const maskInfo = (info) => new Proxy(info, {
    get(target, prop, recv) {
      if (prop === "vendor") return maskedWebGL?.vendor ?? "";
      if (prop === "architecture" || prop === "device") return "";
      if (prop === "description") return maskedWebGL?.renderer ?? "";
      const value = Reflect.get(target, prop, recv);
      return typeof value === "function" ? value.bind(target) : value;
    }
  });
  gpu.requestAdapter = async function(options) {
    const adapter = await orig(options);
    if (!adapter || !engineEnabled || !effectivePolicy.fingerprint) return adapter;
    return new Proxy(adapter, {
      get(target, prop, recv) {
        if (prop === "info" && target.info) return maskInfo(target.info);
        const legacy = target;
        if (prop === "requestAdapterInfo" && typeof legacy.requestAdapterInfo === "function") {
          const requestInfo = legacy.requestAdapterInfo.bind(target);
          return async (...args) => maskInfo(await requestInfo(...args));
        }
        const value = Reflect.get(target, prop, recv);
        return typeof value === "function" ? value.bind(target) : value;
      }
    });
  };
}
function applyFingerprintModule() {
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
let lastStampOut = 0;
function distortStamp(ts) {
  const noise = randFloat(-intensityConfig.jitterMs, intensityConfig.jitterMs);
  let out = Math.max(0, ts + noise);
  if (out < lastStampOut) out = lastStampOut;
  lastStampOut = out;
  return out;
}
function jitterEvent(evt) {
  if (!effectivePolicy.intercept || isCredentialTarget(evt.target)) return evt;
  const stamped = distortStamp(evt.timeStamp);
  return new Proxy(evt, {
    get(target, prop) {
      if (prop === "timeStamp") return stamped;
      const val = Reflect.get(target, prop);
      return typeof val === "function" ? val.bind(target) : val;
    }
  });
}
function patchAddEventListener() {
  const origAdd = EventTarget.prototype.addEventListener;
  const origRemove = EventTarget.prototype.removeEventListener;
  const registry = /* @__PURE__ */ new WeakMap();
  EventTarget.prototype.addEventListener = function(type, listener, options) {
    if (!listener || !INTERCEPT_EVENTS.has(type)) {
      return origAdd.call(this, type, listener, options);
    }
    let wrapped = registry.get(listener)?.get(type);
    if (!wrapped) {
      wrapped = (evt) => {
        const deliver = (event) => {
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
        inner = /* @__PURE__ */ new Map();
        registry.set(listener, inner);
      }
      inner.set(type, wrapped);
    }
    return origAdd.call(this, type, wrapped, options);
  };
  EventTarget.prototype.removeEventListener = function(type, listener, options) {
    const wrapped = listener ? registry.get(listener)?.get(type) : void 0;
    return origRemove.call(this, type, wrapped ?? listener, options);
  };
}
const syntheticEvents = /* @__PURE__ */ new WeakSet();
function markSynthetic(evt) {
  syntheticEvents.add(evt);
}
function buildPointerNoise(base, count) {
  const events = [];
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
      view: window
    };
    const pointer = new PointerEvent("pointermove", {
      ...common,
      pointerId: base instanceof PointerEvent ? base.pointerId : 1,
      pointerType: base instanceof PointerEvent ? base.pointerType : "mouse",
      isPrimary: true
    });
    const mouse = new MouseEvent("mousemove", common);
    markSynthetic(pointer);
    markSynthetic(mouse);
    events.push(pointer, mouse);
  }
  return events;
}
const syntheticQueue = [];
const syntheticTargets = /* @__PURE__ */ new WeakMap();
let flushScheduled = false;
function flushSyntheticQueue() {
  flushScheduled = false;
  const fallback = document.documentElement ?? document.body;
  while (syntheticQueue.length > 0) {
    const next = syntheticQueue.shift();
    if (!next) break;
    const target = syntheticTargets.get(next) ?? fallback;
    if (!target) continue;
    try {
      target.dispatchEvent(next);
    } catch {
    }
  }
}
function scheduleSyntheticFlush() {
  if (flushScheduled || syntheticQueue.length === 0) return;
  flushScheduled = true;
  if (typeof requestIdleCallback !== "undefined") requestIdleCallback(flushSyntheticQueue, { timeout: 50 });
  else setTimeout(flushSyntheticQueue, 0);
}
function enqueuePointerNoise(evt) {
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
    const noise = buildPointerNoise(evt, count);
    const target = evt.target instanceof Node ? evt.target : void 0;
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
function attachPoisonListener() {
  const type = typeof PointerEvent !== "undefined" ? "pointermove" : "mousemove";
  document.addEventListener(type, enqueuePointerNoise, { capture: true, passive: true });
}
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
  /browser-intake[a-z0-9.-]*\.datadoghq\.com$/i
];
const FIRST_PARTY_COLLECTOR = [
  /\/(?:g|j|r)\/collect\/?$/i,
  /\/_\/collect\/?$/i,
  /\/cdn-cgi\/(?:rum|beacon)\b/i,
  /\/(?:matomo|piwik)\.php$/i
];
let customRules = [];
function compileCustomRules(rules) {
  customRules = [];
  for (const rule of rules) {
    if (!rule || rule.length > 200) continue;
    if (/(\([^)]*[+*][^)]*\)){2,}/.test(rule)) continue;
    try {
      customRules.push(new RegExp(rule, "g"));
    } catch {
    }
  }
}
function hostIsTracker(hostname) {
  return TRACKER_HOST.some((re) => re.test(hostname));
}
const APP_HOST_COLLECTORS = [
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
  { host: /(^|\.)logrocket\.com$/i, collector: /^(cdn|r)\./i }
];
function isNarrowTracker(url) {
  const host = url.hostname;
  for (const entry of APP_HOST_COLLECTORS) {
    if (entry.host.test(host)) return entry.collector.test(host);
  }
  return true;
}
function isTelemetryUrl(raw) {
  let url;
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
function passesLuhn(digits) {
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
function redactText(text) {
  if (!text || text.length > MAX_REDACT_CHARS) return { text, changed: false };
  let result = text;
  let changed = false;
  const apply = (next) => {
    if (next !== result) {
      changed = true;
      result = next;
    }
  };
  apply(result.replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[email redacted]"));
  apply(result.replace(
    /\b(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\d{3}[\s.-])\d{3}[\s.-]\d{4}\b/g,
    "[phone redacted]"
  ));
  apply(result.replace(/\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g, "[SSN redacted]"));
  apply(result.replace(/\b\d[\d -]{11,22}\d\b/g, (match) => {
    const digits = match.replace(/\D/g, "");
    return passesLuhn(digits) ? "[card redacted]" : match;
  }));
  apply(result.replace(
    /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    "[IP redacted]"
  ));
  apply(result.replace(
    /\b\d{1,5}\s+\w+\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct)\b/gi,
    "[address redacted]"
  ));
  for (const pattern of customRules) {
    pattern.lastIndex = 0;
    apply(result.replace(pattern, "[custom redacted]"));
  }
  return { text: result, changed };
}
function noteSanitized(detail) {
  pendingSanitized++;
  trackSuccess("sanitize");
  pushActivity("sanitized", detail);
}
function installNetworkRedaction() {
  const origFetch = window.fetch.bind(window);
  window.fetch = function(input, init) {
    if (!engineEnabled || !effectivePolicy.sanitize) return origFetch(input, init);
    const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (!isTelemetryUrl(raw)) return origFetch(input, init);
    return redactFetch(origFetch, input, init, raw);
  };
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;
  const xhrUrls = /* @__PURE__ */ new WeakMap();
  XMLHttpRequest.prototype.open = function(method, url, async, username, password) {
    try {
      xhrUrls.set(this, String(url));
    } catch {
    }
    return origOpen.call(this, method, url, async ?? true, username, password);
  };
  XMLHttpRequest.prototype.send = function(body) {
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
    navigator.sendBeacon = function(url, data) {
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
async function redactFetch(origFetch, input, init, raw) {
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
    } else if (typeof Request !== "undefined" && input instanceof Request && init?.body === void 0) {
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
      mode: init?.mode ?? req.mode
    });
  } catch (err) {
    trackError("sanitize", err);
    return origFetch(input, init);
  }
}
applyFingerprintModule();
patchAddEventListener();
attachPoisonListener();
installNetworkRedaction();
checkSensitiveContext();
setInterval(flushReport, FLUSH_MS);
document.addEventListener("DOMContentLoaded", checkSensitiveContext, { once: true });

})();
