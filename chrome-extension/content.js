(function () {
const SCHEMA_VERSION = 2;
const INTENSITY_CONFIGS = {
  low: { minSynthetic: 1, maxSynthetic: 2, jitterMs: 5, mouseOffset: 30, clickOffset: 10, tokenRefillRate: 5, tokenBucketMax: 30 },
  medium: { minSynthetic: 3, maxSynthetic: 5, jitterMs: 15, mouseOffset: 80, clickOffset: 30, tokenRefillRate: 15, tokenBucketMax: 60 },
  high: { minSynthetic: 6, maxSynthetic: 12, jitterMs: 30, mouseOffset: 150, clickOffset: 60, tokenRefillRate: 30, tokenBucketMax: 100 },
  paranoid: { minSynthetic: 15, maxSynthetic: 20, jitterMs: 50, mouseOffset: 250, clickOffset: 100, tokenRefillRate: 50, tokenBucketMax: 150 }
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
    domainModulePolicy: {}
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



const TRACKED_EVENTS = [
  "mousemove",
  "click",
  "keydown",
  "keyup",
  "scroll",
  "submit"
];
const MAX_QUEUE = 512;
const METRICS_FLUSH_MS = 5e3;
const MAX_ACTIVITY_BUFFER = 20;
const SENSITIVE_URL_RE = /bank|pay(?:ment|pal)?|checkout|billing|wallet|finance|credit|transaction|signin|login|auth/i;
const SYNTHETIC_KEY = "__vitiate_synthetic__";
function isSynthetic(evt) {
  return evt[SYNTHETIC_KEY] === true;
}
function markSynthetic(evt) {
  evt[SYNTHETIC_KEY] = true;
}
let engineEnabled = true;
let currentIntensity = "medium";
let intensityConfig = INTENSITY_CONFIGS.medium;
let effectivePolicy = { intercept: true, poison: true, fingerprint: true, sanitize: true };
let pendingIntercepted = 0;
let pendingSynthetic = 0;
let pendingSanitized = 0;
let activityBuffer = [];
let sensitiveContext = false;
const localCounters = {
  intercept: defaultModuleCounter(),
  poison: defaultModuleCounter(),
  fingerprint: defaultModuleCounter(),
  sanitize: defaultModuleCounter()
};
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
const tokenBucket = {
  tokens: 0,
  lastRefillMs: 0
};
function consumeToken() {
  const nowMs = Date.now();
  const elapsed = (nowMs - tokenBucket.lastRefillMs) / 1e3;
  tokenBucket.tokens = Math.min(
    intensityConfig.tokenBucketMax,
    tokenBucket.tokens + elapsed * intensityConfig.tokenRefillRate
  );
  tokenBucket.lastRefillMs = nowMs;
  if (tokenBucket.tokens >= 1) {
    tokenBucket.tokens -= 1;
    return true;
  }
  return false;
}
function pushActivity(kind, detail) {
  activityBuffer.push({ time: (/* @__PURE__ */ new Date()).toISOString(), kind, detail });
  if (activityBuffer.length >= MAX_ACTIVITY_BUFFER) flushActivity();
}
function flushActivity() {
  if (activityBuffer.length === 0) return;
  const entries = activityBuffer.splice(0);
  chrome.runtime.sendMessage({ type: "REPORT_ACTIVITY", entries }).catch(() => {
  });
}
function trackSuccess(module) {
  localCounters[module].processed++;
  localCounters[module].lastActiveMs = Date.now();
}
function trackError(module, err) {
  localCounters[module].errors++;
  const msg = err instanceof Error ? err.message : String(err);
  reportIncident(module, msg.slice(0, 120));
}
function trackRateLimit(module) {
  localCounters[module].skippedRateLimit++;
}
function reportIncident(module, message) {
  chrome.runtime.sendMessage({
    type: "REPORT_INCIDENT",
    incident: { time: (/* @__PURE__ */ new Date()).toISOString(), domain: location.hostname, module, message }
  }).catch(() => {
  });
}
function checkSensitiveContext() {
  const wasSensitive = sensitiveContext;
  const urlHit = SENSITIVE_URL_RE.test(location.hostname) || SENSITIVE_URL_RE.test(location.pathname);
  const hasPassword = document.querySelector('input[type="password"]') !== null;
  const hasOTP = document.querySelector('[autocomplete="one-time-code"]') !== null;
  sensitiveContext = urlHit || hasPassword || hasOTP;
  if (sensitiveContext && !wasSensitive) {
    reportIncident("poison", "Sensitive page detected — synthetic injection paused for this frame");
    pushActivity("error", "Sensitive context detected — poisoning paused");
  }
}
const PLATFORM_PROFILES = [
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
      ["es-ES", "es"]
    ]
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
      ["de-DE", "de", "en"]
    ]
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
      ["ja-JP", "ja"]
    ]
  }
];
function buildCoherentFingerprintBundle() {
  const profile = PLATFORM_PROFILES[randInt(0, PLATFORM_PROFILES.length - 1)];
  const [sw, sh] = profile.screens[randInt(0, profile.screens.length - 1)];
  const languages = profile.languageSets[randInt(0, profile.languageSets.length - 1)];
  return {
    platform: profile.platform,
    languages,
    hardwareConcurrency: profile.concurrencies[randInt(0, profile.concurrencies.length - 1)],
    deviceMemory: profile.memories[randInt(0, profile.memories.length - 1)],
    screenWidth: sw,
    screenHeight: sh,
    colorDepth: profile.colorDepths[randInt(0, profile.colorDepths.length - 1)],
    canvasNoiseSeed: randInt(1, 65535)
  };
}
let fpBundle = buildCoherentFingerprintBundle();
function applyFingerprintModule() {
  if (!effectivePolicy.fingerprint) return;
  try {
    poisonCanvasFingerprint(fpBundle.canvasNoiseSeed);
    spoofNavigatorAndScreen(fpBundle);
    trackSuccess("fingerprint");
  } catch (err) {
    trackError("fingerprint", err);
  }
}
function poisonCanvasFingerprint(noiseSeed) {
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function(...args) {
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
          img.data[0] = img.data[0] + noiseSeed & 255;
          ctx.putImageData(img, 0, 0);
          return origToDataURL.apply(tmp, args);
        }
      }
    } catch {
    }
    return origToDataURL.apply(this, args);
  };
  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function(callback, type, quality) {
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
          img.data[1] = img.data[1] + noiseSeed & 255;
          ctx.putImageData(img, 0, 0);
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
    if (!engineEnabled || !effectivePolicy.fingerprint) return imageData;
    const len = Math.min(imageData.data.length, 16);
    for (let i = 0; i < len; i += 4) {
      imageData.data[i] = imageData.data[i] + noiseSeed & 255;
    }
    return imageData;
  };
  const poisonWebGL = (proto) => {
    const orig = proto.getParameter;
    proto.getParameter = function(pname) {
      if (!engineEnabled || !effectivePolicy.fingerprint) return orig.call(this, pname);
      const ext = this.getExtension("WEBGL_debug_renderer_info");
      if (ext) {
        if (pname === ext.UNMASKED_VENDOR_WEBGL) return "Generic Vendor";
        if (pname === ext.UNMASKED_RENDERER_WEBGL) return "Generic Renderer";
      }
      return orig.call(this, pname);
    };
  };
  try {
    poisonWebGL(WebGLRenderingContext.prototype);
  } catch {
  }
  try {
    poisonWebGL(WebGL2RenderingContext.prototype);
  } catch {
  }
}
function spoofNavigatorAndScreen(bundle) {
  const def = (obj, prop, value) => {
    try {
      Object.defineProperty(obj, prop, { get: () => value, configurable: true });
    } catch {
    }
  };
  def(navigator, "hardwareConcurrency", bundle.hardwareConcurrency);
  def(navigator, "deviceMemory", bundle.deviceMemory);
  def(navigator, "platform", bundle.platform);
  def(navigator, "languages", bundle.languages);
  def(screen, "width", bundle.screenWidth);
  def(screen, "height", bundle.screenHeight);
  def(screen, "colorDepth", bundle.colorDepth);
  def(screen, "pixelDepth", bundle.colorDepth);
}
const trackedSet = new Set(TRACKED_EVENTS);
const wrapperRegistry = /* @__PURE__ */ new WeakMap();
function getWrapped(l, t) {
  return wrapperRegistry.get(l)?.get(t);
}
function setWrapped(l, t, w) {
  let inner = wrapperRegistry.get(l);
  if (!inner) {
    inner = /* @__PURE__ */ new Map();
    wrapperRegistry.set(l, inner);
  }
  inner.set(t, w);
}
function maybeMutateTimestamp(evt) {
  if (!effectivePolicy.intercept) return evt;
  if (evt.type !== "keydown" && evt.type !== "keyup") return evt;
  const jitter = randFloat(-intensityConfig.jitterMs, intensityConfig.jitterMs);
  return new Proxy(evt, {
    get(target, prop) {
      if (prop === "timeStamp") return Math.max(0, target.timeStamp + jitter);
      const val = Reflect.get(target, prop);
      return typeof val === "function" ? val.bind(target) : val;
    }
  });
}
function patchAddEventListener(proto) {
  const origAdd = proto.addEventListener;
  const origRemove = proto.removeEventListener;
  proto.addEventListener = function(type, listener, options) {
    if (!listener || !trackedSet.has(type) || !effectivePolicy.intercept) {
      return origAdd.call(this, type, listener, options);
    }
    let wrapped = getWrapped(listener, type);
    if (!wrapped) {
      wrapped = (evt) => {
        if (!engineEnabled || isSynthetic(evt)) {
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
  proto.removeEventListener = function(type, listener, options) {
    if (!listener || !trackedSet.has(type)) {
      return origRemove.call(this, type, listener, options);
    }
    const w = getWrapped(listener, type) ?? listener;
    return origRemove.call(this, type, w, options);
  };
}
patchAddEventListener(Window.prototype);
patchAddEventListener(Document.prototype);
patchAddEventListener(Element.prototype);
function generateMouseArc(base, count) {
  const events = [];
  const off = intensityConfig.mouseOffset;
  const targetX = base.clientX + Math.round(randGaussian(0, off / 2));
  const targetY = base.clientY + Math.round(randGaussian(0, off / 2));
  for (let i = 0; i < count; i++) {
    const t = (i + 1) / (count + 1);
    const eased = t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
    const x = Math.round(base.clientX + (targetX - base.clientX) * eased + randGaussian(0, 2));
    const y = Math.round(base.clientY + (targetY - base.clientY) * eased + randGaussian(0, 2));
    const evt = new MouseEvent("mousemove", {
      clientX: x,
      clientY: y,
      screenX: base.screenX + (x - base.clientX),
      screenY: base.screenY + (y - base.clientY),
      movementX: Math.round(randGaussian(0, 4)),
      movementY: Math.round(randGaussian(0, 4)),
      bubbles: true,
      cancelable: true
    });
    markSynthetic(evt);
    events.push(evt);
  }
  return events;
}
function generateSyntheticClick(base) {
  const off = intensityConfig.clickOffset;
  const evt = new MouseEvent("click", {
    clientX: base.clientX + Math.round(randGaussian(0, off / 3)),
    clientY: base.clientY + Math.round(randGaussian(0, off / 3)),
    button: 0,
    bubbles: true,
    cancelable: true
  });
  markSynthetic(evt);
  return evt;
}
const KEY_POOL = "eeeeeeeeeeetttttttttaaaaaaaaoooooooiiiiiiiinnnnnnnsssssssrrrrrrrhhhhhhldddccuuummmfffggppwwyyyybbvvkxjqz ";
const DIGIT_POOL = "0123456789";
function generateRealisticKey(type) {
  const useDigit = xorshift128plus() < 0.1;
  const pool = useDigit ? DIGIT_POOL : KEY_POOL;
  const key = pool[randInt(0, pool.length - 1)];
  let code;
  if (key === " ") code = "Space";
  else if (/\d/.test(key)) code = `Digit${key}`;
  else code = `Key${key.toUpperCase()}`;
  const evt = new KeyboardEvent(type, { key, code, bubbles: true, cancelable: true });
  markSynthetic(evt);
  return evt;
}
function generateSyntheticScroll() {
  const evt = new Event("scroll", { bubbles: true, cancelable: false });
  markSynthetic(evt);
  return evt;
}
const syntheticQueue = [];
let flushScheduled = false;
function scheduleSyntheticFlush() {
  if (flushScheduled) return;
  flushScheduled = true;
  if (typeof requestIdleCallback !== "undefined") {
    requestIdleCallback(flushSyntheticQueue, { timeout: 50 });
  } else {
    setTimeout(flushSyntheticQueue, 0);
  }
}
function flushSyntheticQueue() {
  flushScheduled = false;
  const target = document.documentElement ?? document.body;
  if (!target) return;
  while (syntheticQueue.length > 0) {
    try {
      target.dispatchEvent(syntheticQueue.shift());
    } catch {
    }
  }
}
function enqueueSynthetics(evt) {
  if (!engineEnabled || !effectivePolicy.poison) return;
  if (sensitiveContext) {
    trackRateLimit("poison");
    return;
  }
  if (!consumeToken()) {
    trackRateLimit("poison");
    return;
  }
  if (syntheticQueue.length >= MAX_QUEUE) return;
  const count = randInt(intensityConfig.minSynthetic, intensityConfig.maxSynthetic);
  try {
    switch (evt.type) {
      case "mousemove": {
        const arcs = generateMouseArc(evt, count);
        for (const e of arcs) syntheticQueue.push(e);
        pendingSynthetic += arcs.length;
        break;
      }
      case "click": {
        for (let i = 0; i < count; i++) {
          syntheticQueue.push(generateSyntheticClick(evt));
          pendingSynthetic++;
        }
        break;
      }
      case "keydown":
      case "keyup": {
        for (let i = 0; i < count; i++) {
          syntheticQueue.push(generateRealisticKey(evt.type));
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
function attachEventDelegation() {
  for (const eventType of TRACKED_EVENTS) {
    document.addEventListener(
      eventType,
      (evt) => {
        if (isSynthetic(evt)) return;
        enqueueSynthetics(evt);
      },
      { capture: true, passive: true }
    );
  }
}
const PII_PATTERNS = [
  { pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, replacement: "[email redacted]" },
  { pattern: /(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}/g, replacement: "[phone redacted]" },
  { pattern: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: "[SSN redacted]" },
  { pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, replacement: "[card redacted]" },
  { pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, replacement: "[IP redacted]" },
  {
    pattern: /\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct)\b/gi,
    replacement: "[address redacted]"
  }
];
function sanitizeText(text) {
  let result = text;
  let changed = false;
  for (const { pattern, replacement } of PII_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(result)) {
      changed = true;
      pattern.lastIndex = 0;
      result = result.replace(pattern, replacement);
    }
  }
  return { sanitized: result, changed };
}
function attachPromptSanitization() {
  document.addEventListener(
    "submit",
    (evt) => {
      if (!engineEnabled || !effectivePolicy.sanitize) return;
      const form = evt.target;
      if (!form) return;
      try {
        const textInputs = form.querySelectorAll(
          "textarea, input[type='text'], input[type='search']"
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
        const editables = form.querySelectorAll("[contenteditable='true']");
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
    { capture: true }
  );
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
function attachInputWatcher(root) {
  const targets = [
    ...root.querySelectorAll("textarea, [contenteditable='true']")
  ];
  if (root.matches("textarea") || root.getAttribute("contenteditable") === "true") {
    targets.push(root);
  }
  for (const el of targets) {
    const marker = el;
    if (marker.__vitiate_watched__) continue;
    marker.__vitiate_watched__ = true;
    el.addEventListener("paste", (evt) => {
      if (!engineEnabled || !effectivePolicy.sanitize) return;
      const clip = evt.clipboardData?.getData("text/plain");
      if (!clip) return;
      try {
        const { sanitized, changed } = sanitizeText(clip);
        if (changed) {
          evt.preventDefault();
          if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
            const start = el.selectionStart ?? el.value.length;
            const end = el.selectionEnd ?? el.value.length;
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
function flushMetrics() {
  checkSensitiveContext();
  if (pendingIntercepted > 0) pushActivity("intercepted", `${pendingIntercepted} events intercepted`);
  if (pendingSynthetic > 0) pushActivity("poisoned", `${pendingSynthetic} synthetic events injected`);
  if (pendingIntercepted > 0 || pendingSynthetic > 0 || pendingSanitized > 0) {
    chrome.runtime.sendMessage({
      type: "REPORT_METRICS",
      delta: {
        interceptedEvents: pendingIntercepted,
        syntheticEventsInjected: pendingSynthetic,
        sanitizedInputs: pendingSanitized
      }
    }).catch(() => {
    });
    pendingIntercepted = 0;
    pendingSynthetic = 0;
    pendingSanitized = 0;
  }
  for (const mid of Object.keys(localCounters)) {
    const c = localCounters[mid];
    if (c.processed > 0 || c.errors > 0 || c.skippedRateLimit > 0) {
      chrome.runtime.sendMessage({
        type: "REPORT_MODULE_COUNTER",
        module: mid,
        delta: { processed: c.processed, errors: c.errors, skippedRateLimit: c.skippedRateLimit }
      }).catch(() => {
      });
      localCounters[mid] = { ...defaultModuleCounter(), lastActiveMs: c.lastActiveMs };
    }
  }
  flushActivity();
}
async function init() {
  try {
    const response = await chrome.runtime.sendMessage({
      type: "GET_SETTINGS",
      domain: location.hostname
    });
    if (response?.type === "SETTINGS_RESPONSE") {
      engineEnabled = response.domainEnabled;
      currentIntensity = response.settings.intensity ?? "medium";
      intensityConfig = INTENSITY_CONFIGS[currentIntensity];
      effectivePolicy = response.effectivePolicy ?? effectivePolicy;
    }
  } catch {
    engineEnabled = true;
  }
  tokenBucket.tokens = intensityConfig.tokenBucketMax;
  tokenBucket.lastRefillMs = Date.now();
  fpBundle = buildCoherentFingerprintBundle();
  checkSensitiveContext();
  applyFingerprintModule();
  attachEventDelegation();
  attachPromptSanitization();
  setInterval(flushMetrics, METRICS_FLUSH_MS);
}
init();

})();
