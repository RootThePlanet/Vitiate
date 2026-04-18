/**
 * Vitiate — Content Script
 * Injected at document_start on every frame.
 *
 * Phase 2: Event Interception Layer
 * Phase 3: Data Poisoning Engine (intensity-aware)
 * Phase 4: Semantic Prompt Sanitization
 * Phase 5: Canvas & WebGL Fingerprint Poisoning
 * Phase 6: Navigator & Screen Property Spoofing
 *
 * All processing is local with zero network I/O.
 */

import {
  type VitiateMessage,
  type TrackedEventType,
  type IntensityLevel,
  type IntensityConfig,
  type ActivityEntry,
  INTENSITY_CONFIGS,
} from "../shared/types";

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

/** Maximum queued synthetic events to prevent memory bloat */
const MAX_QUEUE = 512;

/** Flush interval for batched metric reports (ms) */
const METRICS_FLUSH_MS = 5_000;

/** Maximum buffered activity entries before flush */
const MAX_ACTIVITY_BUFFER = 20;

/* ================================================================== */
/*  Runtime state                                                      */
/* ================================================================== */

let engineEnabled = true;
let currentIntensity: IntensityLevel = "medium";
let intensityConfig: IntensityConfig = INTENSITY_CONFIGS.medium;
let pendingIntercepted = 0;
let pendingSynthetic = 0;
let pendingSanitized = 0;
let activityBuffer: ActivityEntry[] = [];

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
/*  Activity feed helper                                               */
/* ================================================================== */

function pushActivity(kind: ActivityEntry["kind"], detail: string): void {
  activityBuffer.push({
    time: new Date().toISOString(),
    kind,
    detail,
  });
  if (activityBuffer.length >= MAX_ACTIVITY_BUFFER) {
    flushActivity();
  }
}

function flushActivity(): void {
  if (activityBuffer.length === 0) return;
  const entries = activityBuffer.splice(0);
  chrome.runtime.sendMessage({ type: "REPORT_ACTIVITY", entries } satisfies VitiateMessage).catch(() => {});
}

/* ================================================================== */
/*  Phase 2: Event Interception Layer                                  */
/* ================================================================== */

const trackedSet = new Set<string>(TRACKED_EVENTS);

const SYNTHETIC_KEY = "__vitiate_synthetic__";

type AnyListener = EventListenerOrEventListenerObject;
type OriginalAddEventListener = typeof EventTarget.prototype.addEventListener;
type OriginalRemoveEventListener = typeof EventTarget.prototype.removeEventListener;

/**
 * Registry that maps each original listener to its per-type wrapped counterpart.
 * WeakMap keys are garbage-collected when the listener is collected, preventing leaks.
 */
const wrapperRegistry = new WeakMap<AnyListener, Map<string, EventListener>>();

function getWrapped(listener: AnyListener, type: string): EventListener | undefined {
  return wrapperRegistry.get(listener)?.get(type);
}

function setWrapped(listener: AnyListener, type: string, wrapped: EventListener): void {
  let inner = wrapperRegistry.get(listener);
  if (!inner) {
    inner = new Map();
    wrapperRegistry.set(listener, inner);
  }
  inner.set(type, wrapped);
}

function patchAddEventListener(proto: EventTarget): void {
  const original: OriginalAddEventListener = proto.addEventListener;
  const originalRemove: OriginalRemoveEventListener = proto.removeEventListener;

  proto.addEventListener = function (
    type: string,
    listener: AnyListener | null,
    options?: boolean | AddEventListenerOptions,
  ): void {
    if (!listener) {
      return original.call(this, type, listener, options);
    }

    if (!trackedSet.has(type)) {
      return original.call(this, type, listener, options);
    }

    // Reuse an existing wrapper if one was already registered for this listener+type
    // so that duplicate addEventListener calls are handled consistently.
    let wrappedListener = getWrapped(listener, type);
    if (!wrappedListener) {
      wrappedListener = (evt: Event) => {
        if (!engineEnabled || (evt as unknown as Record<string, unknown>)[SYNTHETIC_KEY]) {
          if (typeof listener === "function") {
            listener(evt);
          } else {
            listener.handleEvent(evt);
          }
          return;
        }

        pendingIntercepted++;

        const mutated = maybeMutateTimestamp(evt);
        if (typeof listener === "function") {
          listener(mutated);
        } else {
          listener.handleEvent(mutated);
        }
      };
      setWrapped(listener, type, wrappedListener);
    }

    return original.call(this, type, wrappedListener, options);
  };

  // Mirror removeEventListener so callers can cleanly deregister the original listener
  // reference even though the browser registered the wrapped version.
  proto.removeEventListener = function (
    type: string,
    listener: AnyListener | null,
    options?: boolean | EventListenerOptions,
  ): void {
    if (!listener || !trackedSet.has(type)) {
      return originalRemove.call(this, type, listener, options);
    }
    const wrapped = getWrapped(listener, type) ?? listener;
    return originalRemove.call(this, type, wrapped, options);
  };
}

// Apply patches
patchAddEventListener(Window.prototype);
patchAddEventListener(Document.prototype);
patchAddEventListener(Element.prototype);

/* ================================================================== */
/*  Phase 3: Data Poisoning Engine (intensity-aware)                   */
/* ================================================================== */

function maybeMutateTimestamp(evt: Event): Event {
  if (evt.type !== "keydown" && evt.type !== "keyup") return evt;

  const jitter = randFloat(-intensityConfig.jitterMs, intensityConfig.jitterMs);
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
    const evt = syntheticQueue.shift()!;
    try {
      target.dispatchEvent(evt);
    } catch {
      // Swallow errors from synthetic dispatch
    }
  }
}

function generateSyntheticMouseMove(baseEvent: MouseEvent): MouseEvent {
  const off = intensityConfig.mouseOffset;
  return new MouseEvent("mousemove", {
    clientX: baseEvent.clientX + randInt(-off, off),
    clientY: baseEvent.clientY + randInt(-off, off),
    screenX: baseEvent.screenX + randInt(-off, off),
    screenY: baseEvent.screenY + randInt(-off, off),
    movementX: randInt(-20, 20),
    movementY: randInt(-20, 20),
    bubbles: true,
    cancelable: true,
  });
}

function generateSyntheticClick(baseEvent: MouseEvent): MouseEvent {
  const off = intensityConfig.clickOffset;
  return new MouseEvent("click", {
    clientX: baseEvent.clientX + randInt(-off, off),
    clientY: baseEvent.clientY + randInt(-off, off),
    button: 0,
    bubbles: true,
    cancelable: true,
  });
}

function generateSyntheticKey(
  type: "keydown" | "keyup",
  _baseEvent: KeyboardEvent,
): KeyboardEvent {
  const letters = "abcdefghijklmnopqrstuvwxyz";
  const digits = "0123456789";
  const all = letters + digits + " ";
  const key = all[randInt(0, all.length - 1)];

  let code: string;
  if (key === " ") {
    code = "Space";
  } else if (digits.includes(key)) {
    code = `Digit${key}`;
  } else {
    code = `Key${key.toUpperCase()}`;
  }

  return new KeyboardEvent(type, {
    key,
    code,
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

  const count = randInt(intensityConfig.minSynthetic, intensityConfig.maxSynthetic);

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
    }

    if (synthetic) {
      (synthetic as unknown as Record<string, unknown>)[SYNTHETIC_KEY] = true;
      syntheticQueue.push(synthetic);
      pendingSynthetic++;
    }
  }

  scheduleSyntheticFlush();
}

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

const PII_PATTERNS: { pattern: RegExp; replacement: string }[] = [
  {
    pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    replacement: "[email redacted]",
  },
  {
    pattern: /(\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}/g,
    replacement: "[phone redacted]",
  },
  {
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    replacement: "[SSN redacted]",
  },
  {
    pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    replacement: "[card redacted]",
  },
  {
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    replacement: "[IP redacted]",
  },
  {
    pattern: /\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct)\b/gi,
    replacement: "[address redacted]",
  },
];

function sanitizeText(text: string): { sanitized: string; changed: boolean } {
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

function attachPromptSanitization(): void {
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
          pushActivity("sanitized", "PII redacted from form input");
        }
      }

      const editables = form.querySelectorAll<HTMLElement>("[contenteditable='true']");
      for (const el of editables) {
        const { sanitized, changed } = sanitizeText(el.innerText);
        if (changed) {
          el.innerText = sanitized;
          pendingSanitized++;
          pushActivity("sanitized", "PII redacted from contenteditable");
        }
      }
    },
    { capture: true },
  );

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
        if (el instanceof HTMLTextAreaElement || el instanceof HTMLInputElement) {
          // Use setRangeText for reliable insertion into form fields
          const start = el.selectionStart ?? el.value.length;
          const end = el.selectionEnd ?? el.value.length;
          el.setRangeText(sanitized, start, end, "end");
        } else {
          // contenteditable: use Selection + Range API
          const selection = window.getSelection();
          if (selection && selection.rangeCount > 0) {
            const range = selection.getRangeAt(0);
            range.deleteContents();
            range.insertNode(document.createTextNode(sanitized));
            range.collapse(false);
            selection.removeAllRanges();
            selection.addRange(range);
          }
        }
        pendingSanitized++;
        pushActivity("sanitized", "PII redacted from paste");
      }
    });
  }
}

/* ================================================================== */
/*  Phase 5: Canvas & WebGL Fingerprint Poisoning                      */
/* ================================================================== */

/**
 * Inject deterministic per-session noise into canvas fingerprinting
 * APIs. The noise is seeded from the PRNG so it's consistent within
 * a single session but changes across sessions.
 */
function poisonCanvasFingerprint(): void {
  // Cache one noise byte per session for deterministic poisoning
  const noiseSeed = randInt(1, 255);

  // Poison HTMLCanvasElement.prototype.toDataURL
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function (
    ...args: Parameters<typeof origToDataURL>
  ): string {
    if (!engineEnabled) return origToDataURL.apply(this, args);

    // Work on a temporary copy so the original canvas pixels are never mutated
    try {
      if (this.width > 0 && this.height > 0) {
        const tmp = document.createElement("canvas");
        tmp.width = this.width;
        tmp.height = this.height;
        const tmpCtx = tmp.getContext("2d");
        if (tmpCtx) {
          tmpCtx.drawImage(this, 0, 0);
          const imgData = tmpCtx.getImageData(0, 0, 1, 1);
          imgData.data[0] = (imgData.data[0] + noiseSeed) & 0xff;
          tmpCtx.putImageData(imgData, 0, 0);
          return origToDataURL.apply(tmp, args);
        }
      }
    } catch {
      // Tainted (cross-origin) or zero-size canvas — fall through
    }
    return origToDataURL.apply(this, args);
  };

  // Poison HTMLCanvasElement.prototype.toBlob
  const origToBlob = HTMLCanvasElement.prototype.toBlob;
  HTMLCanvasElement.prototype.toBlob = function (
    callback: BlobCallback,
    type?: string,
    quality?: number,
  ): void {
    if (!engineEnabled) return origToBlob.call(this, callback, type, quality);

    // Work on a temporary copy so the original canvas pixels are never mutated
    try {
      if (this.width > 0 && this.height > 0) {
        const tmp = document.createElement("canvas");
        tmp.width = this.width;
        tmp.height = this.height;
        const tmpCtx = tmp.getContext("2d");
        if (tmpCtx) {
          tmpCtx.drawImage(this, 0, 0);
          const imgData = tmpCtx.getImageData(0, 0, 1, 1);
          imgData.data[1] = (imgData.data[1] + noiseSeed) & 0xff;
          tmpCtx.putImageData(imgData, 0, 0);
          return origToBlob.call(tmp, callback, type, quality);
        }
      }
    } catch {
      // Tainted (cross-origin) or zero-size canvas — fall through
    }
    return origToBlob.call(this, callback, type, quality);
  };

  // Poison CanvasRenderingContext2D.prototype.getImageData
  const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (
    ...args: Parameters<typeof origGetImageData>
  ): ImageData {
    const imageData = origGetImageData.apply(this, args);
    if (!engineEnabled) return imageData;

    // Add subtle noise to first few pixels
    const len = Math.min(imageData.data.length, 16);
    for (let i = 0; i < len; i += 4) {
      imageData.data[i] = (imageData.data[i] + noiseSeed) & 0xff;
    }
    return imageData;
  };

  // Poison WebGLRenderingContext.getParameter for renderer/vendor queries
  const poisonWebGLGetParameter = (proto: WebGLRenderingContext | WebGL2RenderingContext) => {
    const origGetParam = proto.getParameter;
    proto.getParameter = function (pname: GLenum): ReturnType<typeof origGetParam> {
      if (!engineEnabled) return origGetParam.call(this, pname);

      const debugExt = this.getExtension("WEBGL_debug_renderer_info");
      if (debugExt) {
        // UNMASKED_VENDOR_WEBGL = 0x9245, UNMASKED_RENDERER_WEBGL = 0x9246
        if (pname === debugExt.UNMASKED_VENDOR_WEBGL) {
          return "Generic Vendor";
        }
        if (pname === debugExt.UNMASKED_RENDERER_WEBGL) {
          return "Generic Renderer";
        }
      }
      return origGetParam.call(this, pname);
    };
  };

  try {
    poisonWebGLGetParameter(WebGLRenderingContext.prototype);
  } catch {
    // WebGL not available
  }
  try {
    poisonWebGLGetParameter(WebGL2RenderingContext.prototype);
  } catch {
    // WebGL2 not available
  }
}

/* ================================================================== */
/*  Phase 6: Navigator & Screen Property Spoofing                      */
/* ================================================================== */

/**
 * Override common passive fingerprinting properties with randomized
 * per-session values. Values are plausible and consistent within
 * a single session.
 */
function spoofNavigatorAndScreen(): void {
  // Generate plausible per-session values using array-length-derived bounds
  const concurrencyOptions = [2, 4, 8, 12, 16];
  const spoofedConcurrency = concurrencyOptions[randInt(0, concurrencyOptions.length - 1)];
  const memoryOptions = [2, 4, 8, 16];
  const spoofedMemory = memoryOptions[randInt(0, memoryOptions.length - 1)];
  const platformOptions = ["Win32", "Linux x86_64", "MacIntel"];
  const spoofedPlatform = platformOptions[randInt(0, platformOptions.length - 1)];
  const languageOptions: readonly string[][] = [
    ["en-US", "en"],
    ["en-GB", "en"],
    ["en-US"],
    ["en-US", "en", "es"],
  ];
  const spoofedLanguages: readonly string[] = languageOptions[randInt(0, languageOptions.length - 1)];
  const colorDepthOptions = [24, 30, 32];
  const spoofedColorDepth = colorDepthOptions[randInt(0, colorDepthOptions.length - 1)];
  const resolutions = [
    [1920, 1080],
    [2560, 1440],
    [1366, 768],
    [1440, 900],
    [1536, 864],
  ];
  const [spoofedWidth, spoofedHeight] = resolutions[randInt(0, resolutions.length - 1)];

  const defineReadonly = (obj: object, prop: string, value: unknown) => {
    try {
      Object.defineProperty(obj, prop, {
        get: () => value,
        configurable: true,
      });
    } catch {
      // Property may not be configurable in some browsers
    }
  };

  defineReadonly(navigator, "hardwareConcurrency", spoofedConcurrency);
  defineReadonly(navigator, "deviceMemory", spoofedMemory);
  defineReadonly(navigator, "platform", spoofedPlatform);
  defineReadonly(navigator, "languages", spoofedLanguages);
  defineReadonly(screen, "width", spoofedWidth);
  defineReadonly(screen, "height", spoofedHeight);
  defineReadonly(screen, "colorDepth", spoofedColorDepth);
  defineReadonly(screen, "pixelDepth", spoofedColorDepth);
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
    flushActivity();
    return;
  }

  // Report aggregate activity entries
  if (pendingIntercepted > 0) {
    pushActivity("intercepted", `${pendingIntercepted} events intercepted`);
  }
  if (pendingSynthetic > 0) {
    pushActivity("poisoned", `${pendingSynthetic} synthetic events injected`);
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

  flushActivity();
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
      currentIntensity = response.settings.intensity ?? "medium";
      intensityConfig = INTENSITY_CONFIGS[currentIntensity];
    }
  } catch {
    // First run or extension context invalid — default to enabled
    engineEnabled = true;
  }

  // Apply fingerprint protections early (before page scripts run)
  poisonCanvasFingerprint();
  spoofNavigatorAndScreen();

  attachEventDelegation();
  attachPromptSanitization();

  // Periodically flush metrics
  setInterval(flushMetrics, METRICS_FLUSH_MS);
}

init();
