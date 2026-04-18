/**
 * Vitiate — Background Service Worker (Manifest V3)  v2
 *
 * Responsibilities:
 * 1. Persist and serve VitiateSettings via chrome.storage.local (with schema migration)
 * 2. Aggregate per-session and lifetime metrics reported by content scripts
 * 3. Relay state between popup ↔ content via chrome.runtime messaging
 * 4. Manage toolbar badge (live event count + status color)
 * 5. Handle keyboard shortcut quick-toggle
 * 6. Maintain real-time activity feed
 * 7. Aggregate module-level counters from content scripts          [v2]
 * 8. Deduplicate and store site-compatibility incident log          [v2]
 * 9. Compute health status from aggregated counters                [v2]
 * 10. Produce exportable local diagnostics snapshot                [v2]
 *
 * Zero network I/O — all processing is local.
 */

import {
  type VitiateMessage,
  type VitiateSettings,
  type SessionMetrics,
  type LifetimeMetrics,
  type ActivityEntry,
  type IncidentEntry,
  type HealthStatus,
  type ModuleId,
  type ModuleCounter,
  type DiagnosticsSnapshot,
  defaultSettings,
  defaultMetrics,
  defaultLifetimeMetrics,
  defaultModuleCounter,
  formatCompactNumber,
  migrateSettings,
  getPolicyReason,
  getEffectiveModulePolicy,
  isDomainEnabled,
  SCHEMA_VERSION,
} from "../shared/types";

/* ------------------------------------------------------------------ */
/*  In-memory session state (reset each time the SW spins up)         */
/* ------------------------------------------------------------------ */

let sessionMetrics: SessionMetrics = defaultMetrics();

/** Circular buffer for the real-time activity feed (last 50 entries) */
const MAX_FEED = 50;
let activityFeed: ActivityEntry[] = [];

/** Circular buffer for site-compatibility incidents (last 100) */
const MAX_INCIDENTS = 100;
let incidents: IncidentEntry[] = [];

/** Aggregated per-module counters (reset by RESET_METRICS) */
const moduleCounters: Record<ModuleId, ModuleCounter> = {
  intercept:   defaultModuleCounter(),
  poison:      defaultModuleCounter(),
  fingerprint: defaultModuleCounter(),
  sanitize:    defaultModuleCounter(),
};

/* ------------------------------------------------------------------ */
/*  Settings helpers                                                   */
/* ------------------------------------------------------------------ */

async function loadSettings(): Promise<VitiateSettings> {
  const result = await chrome.storage.local.get("vitiate_settings");
  const stored = result.vitiate_settings as Record<string, unknown> | undefined;
  if (!stored) return defaultSettings();
  return migrateSettings(stored);
}

async function saveSettings(settings: VitiateSettings): Promise<void> {
  await chrome.storage.local.set({ vitiate_settings: settings });
}

/* ------------------------------------------------------------------ */
/*  Lifetime metrics helpers                                           */
/* ------------------------------------------------------------------ */

async function loadLifetimeMetrics(): Promise<LifetimeMetrics> {
  const result = await chrome.storage.local.get("vitiate_lifetime");
  return (result.vitiate_lifetime as LifetimeMetrics) ?? defaultLifetimeMetrics();
}

async function saveLifetimeMetrics(metrics: LifetimeMetrics): Promise<void> {
  await chrome.storage.local.set({ vitiate_lifetime: metrics });
}

/* ------------------------------------------------------------------ */
/*  Health helpers                                                     */
/* ------------------------------------------------------------------ */

/** Health-status computation thresholds */
const HEALTH_ERROR_THRESHOLD    = 10;
const HEALTH_DEGRADED_THRESHOLD = 100;

async function computeHealth(): Promise<HealthStatus> {
  const settings = await loadSettings();
  if (!settings.enabled) return "disabled";

  const totalErrors = Object.values(moduleCounters).reduce((s, c) => s + c.errors, 0);
  if (totalErrors > HEALTH_ERROR_THRESHOLD) return "error";

  const totalSkipped = Object.values(moduleCounters).reduce((s, c) => s + c.skippedRateLimit, 0);
  if (totalSkipped > HEALTH_DEGRADED_THRESHOLD) return "degraded";

  return "active";
}

/* ------------------------------------------------------------------ */
/*  Metrics helpers                                                    */
/* ------------------------------------------------------------------ */

function getTimelineKey(): string {
  const d = new Date();
  return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`;
}

async function applyMetricsDelta(delta: Partial<SessionMetrics>): Promise<void> {
  if (delta.interceptedEvents)       sessionMetrics.interceptedEvents       += delta.interceptedEvents;
  if (delta.syntheticEventsInjected) sessionMetrics.syntheticEventsInjected += delta.syntheticEventsInjected;
  if (delta.sanitizedInputs)         sessionMetrics.sanitizedInputs         += delta.sanitizedInputs;

  const key = getTimelineKey();
  if (!sessionMetrics.timeline[key]) {
    sessionMetrics.timeline[key] = { intercepted: 0, poisoned: 0 };
  }
  sessionMetrics.timeline[key].intercepted += delta.interceptedEvents       ?? 0;
  sessionMetrics.timeline[key].poisoned    += delta.syntheticEventsInjected ?? 0;

  const lifetime = await loadLifetimeMetrics();
  lifetime.interceptedEvents       += delta.interceptedEvents       ?? 0;
  lifetime.syntheticEventsInjected += delta.syntheticEventsInjected ?? 0;
  lifetime.sanitizedInputs         += delta.sanitizedInputs         ?? 0;
  await saveLifetimeMetrics(lifetime);

  await updateBadge();
}

/* ------------------------------------------------------------------ */
/*  Toolbar badge                                                      */
/* ------------------------------------------------------------------ */

async function updateBadge(): Promise<void> {
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

/* ------------------------------------------------------------------ */
/*  Message router                                                     */
/* ------------------------------------------------------------------ */

chrome.runtime.onMessage.addListener(
  (
    message: VitiateMessage,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: VitiateMessage) => void,
  ) => {
    handleMessage(message, sender, sendResponse);
    return true; // keep the message channel open for async sendResponse
  },
);

async function handleMessage(
  msg: VitiateMessage,
  _sender: chrome.runtime.MessageSender,
  sendResponse: (response: VitiateMessage) => void,
): Promise<void> {
  switch (msg.type) {

    /* ── settings ──────────────────────────────────────────────── */
    case "GET_SETTINGS": {
      const settings = await loadSettings();
      const domainEnabled  = isDomainEnabled(settings, msg.domain);
      const policyReason   = getPolicyReason(settings, msg.domain);
      const effectivePolicy = getEffectiveModulePolicy(settings, msg.domain);
      sendResponse({ type: "SETTINGS_RESPONSE", settings, domainEnabled, policyReason, effectivePolicy });
      break;
    }
    case "UPDATE_SETTINGS": {
      const current = await loadSettings();
      const merged: VitiateSettings = { ...current, ...msg.settings };
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
      activityFeed   = [];
      for (const id of Object.keys(moduleCounters) as ModuleId[]) {
        moduleCounters[id] = defaultModuleCounter();
      }
      await updateBadge();
      break;
    }

    /* ── v2: module counters + incidents ───────────────────────── */
    case "REPORT_MODULE_COUNTER": {
      const c = moduleCounters[msg.module];
      if (msg.delta.processed)        c.processed        += msg.delta.processed;
      if (msg.delta.errors)           c.errors           += msg.delta.errors;
      if (msg.delta.skippedRateLimit) c.skippedRateLimit += msg.delta.skippedRateLimit;
      c.lastActiveMs = Date.now();
      break;
    }
    case "REPORT_INCIDENT": {
      const existing = incidents.find(
        (i) =>
          i.domain  === msg.incident.domain &&
          i.module  === msg.incident.module &&
          i.message === msg.incident.message,
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
      const settings  = await loadSettings();
      const lifetime  = await loadLifetimeMetrics();
      const health    = await computeHealth();
      const snapshot: DiagnosticsSnapshot = {
        vitiateVersion: chrome.runtime.getManifest().version,
        exportedAt:     new Date().toISOString(),
        schemaVersion:  SCHEMA_VERSION,
        settings,
        sessionMetrics,
        lifetimeMetrics: lifetime,
        moduleCounters:  { ...moduleCounters },
        incidents:       [...incidents],
        health,
      };
      sendResponse({ type: "SNAPSHOT_RESPONSE", snapshot });
      break;
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Keyboard shortcut handler (Alt+Shift+V toggle)                    */
/* ------------------------------------------------------------------ */

chrome.commands.onCommand.addListener(async (command: string) => {
  if (command === "toggle-protection") {
    const settings = await loadSettings();
    settings.enabled = !settings.enabled;
    await saveSettings(settings);
    await updateBadge();
  }
});

/* ------------------------------------------------------------------ */
/*  Extension lifecycle                                                */
/* ------------------------------------------------------------------ */

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get("vitiate_settings");
  if (!existing.vitiate_settings) {
    await saveSettings(defaultSettings());
  } else {
    // Migrate on upgrade (no-op when already at SCHEMA_VERSION)
    const migrated = migrateSettings(existing.vitiate_settings as Record<string, unknown>);
    await saveSettings(migrated);
  }
  await updateBadge();
});
