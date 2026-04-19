import { S as SCHEMA_VERSION, d as defaultMetrics, a as defaultModuleCounter, i as isDomainEnabled, g as getPolicyReason, b as getEffectiveModulePolicy, m as migrateSettings, c as defaultSettings, e as defaultLifetimeMetrics, f as formatCompactNumber } from './chunks/types-ytiEMfIF.js';

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
  const result = await chrome.storage.local.get("vitiate_settings");
  const stored = result.vitiate_settings;
  if (!stored) return defaultSettings();
  return migrateSettings(stored);
}
async function saveSettings(settings) {
  await chrome.storage.local.set({ vitiate_settings: settings });
}
async function loadLifetimeMetrics() {
  const result = await chrome.storage.local.get("vitiate_lifetime");
  return result.vitiate_lifetime ?? defaultLifetimeMetrics();
}
async function saveLifetimeMetrics(metrics) {
  await chrome.storage.local.set({ vitiate_lifetime: metrics });
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
    await chrome.action.setBadgeText({ text: "OFF" });
    await chrome.action.setBadgeBackgroundColor({ color: "#6b7280" });
    return;
  }
  const total = sessionMetrics.interceptedEvents + sessionMetrics.syntheticEventsInjected;
  const text = total === 0 ? "" : formatCompactNumber(total);
  await chrome.action.setBadgeText({ text });
  await chrome.action.setBadgeBackgroundColor({ color: "#34d399" });
}
chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {
    handleMessage(message, sender, sendResponse);
    return true;
  }
);
async function handleMessage(msg, _sender, sendResponse) {
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
      break;
    }
    case "UPDATE_MODULE_POLICY": {
      const settings = await loadSettings();
      settings.modulePolicy = { ...settings.modulePolicy, ...msg.policy };
      await saveSettings(settings);
      break;
    }
    case "TOGGLE_DOMAIN": {
      const settings = await loadSettings();
      settings.domainOverrides[msg.domain] = msg.enabled;
      await saveSettings(settings);
      break;
    }
    case "REMOVE_DOMAIN": {
      const settings = await loadSettings();
      delete settings.domainOverrides[msg.domain];
      await saveSettings(settings);
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
      break;
    }
    case "REPORT_ACTIVITY": {
      for (const entry of msg.entries) activityFeed.push(entry);
      if (activityFeed.length > MAX_FEED) activityFeed = activityFeed.slice(-MAX_FEED);
      break;
    }
    case "RESET_METRICS": {
      sessionMetrics = defaultMetrics();
      activityFeed = [];
      for (const id of Object.keys(moduleCounters)) {
        moduleCounters[id] = defaultModuleCounter();
      }
      await updateBadge();
      break;
    }
    /* ── v2: module counters + incidents ───────────────────────── */
    case "REPORT_MODULE_COUNTER": {
      const c = moduleCounters[msg.module];
      if (msg.delta.processed) c.processed += msg.delta.processed;
      if (msg.delta.errors) c.errors += msg.delta.errors;
      if (msg.delta.skippedRateLimit) c.skippedRateLimit += msg.delta.skippedRateLimit;
      c.lastActiveMs = Date.now();
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
        vitiateVersion: chrome.runtime.getManifest().version,
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
  }
}
chrome.commands.onCommand.addListener(async (command) => {
  if (command === "toggle-protection") {
    const settings = await loadSettings();
    settings.enabled = !settings.enabled;
    await saveSettings(settings);
    await updateBadge();
  }
});
chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get("vitiate_settings");
  if (!existing.vitiate_settings) {
    await saveSettings(defaultSettings());
  } else {
    const migrated = migrateSettings(existing.vitiate_settings);
    await saveSettings(migrated);
  }
  await updateBadge();
});
