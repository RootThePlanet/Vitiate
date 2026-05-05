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

const globalWithBrowser = globalThis;
const extensionApi = globalWithBrowser.browser ?? chrome;



let sessionMetrics = defaultMetrics();
const MAX_FEED = 50;
let activityFeed = [];
const MAX_INCIDENTS = 100;
let incidents = [];
const moduleCounters = {
  intercept: defaultModuleCounter(),
  poison: defaultModuleCounter(),
  fingerprint: defaultModuleCounter(),
  sanitize: defaultModuleCounter()
};
async function loadSettings() {
  const result = await extensionApi.storage.local.get("vitiate_settings");
  const stored = result.vitiate_settings;
  if (!stored) return defaultSettings();
  return migrateSettings(stored);
}
async function saveSettings(settings) {
  await extensionApi.storage.local.set({ vitiate_settings: settings });
}
async function loadLifetimeMetrics() {
  const result = await extensionApi.storage.local.get("vitiate_lifetime");
  return result.vitiate_lifetime ?? defaultLifetimeMetrics();
}
async function saveLifetimeMetrics(metrics) {
  await extensionApi.storage.local.set({ vitiate_lifetime: metrics });
}
const HEALTH_ERROR_THRESHOLD = 10;
const HEALTH_DEGRADED_THRESHOLD = 100;
async function computeHealth() {
  const settings = await loadSettings();
  if (!settings.enabled) return "disabled";
  const totalErrors = Object.values(moduleCounters).reduce((s, c) => s + c.errors, 0);
  if (totalErrors > HEALTH_ERROR_THRESHOLD) return "error";
  const totalSkipped = Object.values(moduleCounters).reduce((s, c) => s + c.skippedRateLimit, 0);
  if (totalSkipped > HEALTH_DEGRADED_THRESHOLD) return "degraded";
  return "active";
}
function getTimelineKey() {
  const d = /* @__PURE__ */ new Date();
  return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`;
}
async function applyMetricsDelta(delta) {
  if (delta.interceptedEvents) sessionMetrics.interceptedEvents += delta.interceptedEvents;
  if (delta.syntheticEventsInjected) sessionMetrics.syntheticEventsInjected += delta.syntheticEventsInjected;
  if (delta.sanitizedInputs) sessionMetrics.sanitizedInputs += delta.sanitizedInputs;
  const key = getTimelineKey();
  if (!sessionMetrics.timeline[key]) {
    sessionMetrics.timeline[key] = { intercepted: 0, poisoned: 0 };
  }
  sessionMetrics.timeline[key].intercepted += delta.interceptedEvents ?? 0;
  sessionMetrics.timeline[key].poisoned += delta.syntheticEventsInjected ?? 0;
  const lifetime = await loadLifetimeMetrics();
  lifetime.interceptedEvents += delta.interceptedEvents ?? 0;
  lifetime.syntheticEventsInjected += delta.syntheticEventsInjected ?? 0;
  lifetime.sanitizedInputs += delta.sanitizedInputs ?? 0;
  await saveLifetimeMetrics(lifetime);
  await updateBadge();
}
async function updateBadge() {
  const settings = await loadSettings();
  if (!settings.enabled) {
    await extensionApi.action.setBadgeText({ text: "OFF" });
    await extensionApi.action.setBadgeBackgroundColor({ color: "#6b7280" });
    return;
  }
  const total = sessionMetrics.interceptedEvents + sessionMetrics.syntheticEventsInjected;
  const text = total === 0 ? "" : formatCompactNumber(total);
  await extensionApi.action.setBadgeText({ text });
  await extensionApi.action.setBadgeBackgroundColor({ color: "#34d399" });
}
extensionApi.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {
    handleMessage(message, sender, sendResponse);
    return true;
  }
);
async function handleMessage(msg, _sender, sendResponse) {
  try {
    switch (msg.type) {
      /* ── settings ──────────────────────────────────────────────── */
      case "GET_SETTINGS": {
        const settings = await loadSettings();
        const domainEnabled = isDomainEnabled(settings, msg.domain);
        const policyReason = getPolicyReason(settings, msg.domain);
        const effectivePolicy = getEffectiveModulePolicy(settings, msg.domain);
        sendResponse({ type: "SETTINGS_RESPONSE", settings, domainEnabled, policyReason, effectivePolicy });
        break;
      }
      case "UPDATE_SETTINGS": {
        const current = await loadSettings();
        const merged = { ...current, ...msg.settings };
        await saveSettings(merged);
        await updateBadge();
        sendResponse({ type: "ACK" });
        break;
      }
      case "UPDATE_MODULE_POLICY": {
        const settings = await loadSettings();
        settings.modulePolicy = { ...settings.modulePolicy, ...msg.policy };
        await saveSettings(settings);
        sendResponse({ type: "ACK" });
        break;
      }
      case "TOGGLE_DOMAIN": {
        const settings = await loadSettings();
        settings.domainOverrides[msg.domain] = msg.enabled;
        await saveSettings(settings);
        sendResponse({ type: "ACK" });
        break;
      }
      case "REMOVE_DOMAIN": {
        const settings = await loadSettings();
        delete settings.domainOverrides[msg.domain];
        await saveSettings(settings);
        sendResponse({ type: "ACK" });
        break;
      }
      /* ── metrics ───────────────────────────────────────────────── */
      case "GET_METRICS": {
        const lifetime = await loadLifetimeMetrics();
        sendResponse({ type: "METRICS_RESPONSE", metrics: sessionMetrics, lifetime, feed: activityFeed });
        break;
      }
      case "REPORT_METRICS": {
        await applyMetricsDelta(msg.delta);
        sendResponse({ type: "ACK" });
        break;
      }
      case "REPORT_ACTIVITY": {
        for (const entry of msg.entries) activityFeed.push(entry);
        if (activityFeed.length > MAX_FEED) activityFeed = activityFeed.slice(-MAX_FEED);
        sendResponse({ type: "ACK" });
        break;
      }
      case "RESET_METRICS": {
        sessionMetrics = defaultMetrics();
        activityFeed = [];
        for (const id of Object.keys(moduleCounters)) {
          moduleCounters[id] = defaultModuleCounter();
        }
        await updateBadge();
        sendResponse({ type: "ACK" });
        break;
      }
      /* ── v2: module counters + incidents ───────────────────────── */
      case "REPORT_MODULE_COUNTER": {
        const c = moduleCounters[msg.module];
        if (msg.delta.processed) c.processed += msg.delta.processed;
        if (msg.delta.errors) c.errors += msg.delta.errors;
        if (msg.delta.skippedRateLimit) c.skippedRateLimit += msg.delta.skippedRateLimit;
        c.lastActiveMs = Date.now();
        sendResponse({ type: "ACK" });
        break;
      }
      case "REPORT_INCIDENT": {
        const existing = incidents.find(
          (i) => i.domain === msg.incident.domain && i.module === msg.incident.module && i.message === msg.incident.message
        );
        if (existing) {
          existing.count++;
          existing.time = msg.incident.time;
        } else {
          incidents.push({ ...msg.incident, count: 1 });
          if (incidents.length > MAX_INCIDENTS) incidents = incidents.slice(-MAX_INCIDENTS);
        }
        sendResponse({ type: "ACK" });
        break;
      }
      case "GET_HEALTH": {
        const health = await computeHealth();
        sendResponse({ type: "HEALTH_RESPONSE", health, incidents: incidents.slice(-20) });
        break;
      }
      case "GET_MODULE_COUNTERS": {
        sendResponse({ type: "MODULE_COUNTERS_RESPONSE", counters: { ...moduleCounters } });
        break;
      }
      /* ── v2: diagnostics snapshot ──────────────────────────────── */
      case "EXPORT_SNAPSHOT": {
        const settings = await loadSettings();
        const lifetime = await loadLifetimeMetrics();
        const health = await computeHealth();
        const snapshot = {
          vitiateVersion: extensionApi.runtime.getManifest().version,
          exportedAt: (/* @__PURE__ */ new Date()).toISOString(),
          schemaVersion: SCHEMA_VERSION,
          settings,
          sessionMetrics,
          lifetimeMetrics: lifetime,
          moduleCounters: { ...moduleCounters },
          incidents: [...incidents],
          health
        };
        sendResponse({ type: "SNAPSHOT_RESPONSE", snapshot });
        break;
      }
      default:
        sendResponse({ type: "ERROR", message: "Unsupported message type" });
    }
  } catch (err) {
    sendResponse({
      type: "ERROR",
      message: err instanceof Error ? err.message : String(err)
    });
  }
}
extensionApi.commands.onCommand.addListener(async (command) => {
  if (command === "toggle-protection") {
    const settings = await loadSettings();
    settings.enabled = !settings.enabled;
    await saveSettings(settings);
    await updateBadge();
  }
});
extensionApi.runtime.onInstalled.addListener(async () => {
  const existing = await extensionApi.storage.local.get("vitiate_settings");
  if (!existing.vitiate_settings) {
    await saveSettings(defaultSettings());
  } else {
    const migrated = migrateSettings(existing.vitiate_settings);
    await saveSettings(migrated);
  }
  await updateBadge();
});

})();
