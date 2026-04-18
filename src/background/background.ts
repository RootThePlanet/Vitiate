/**
 * Vitiate — Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 * 1. Persist and serve VitiateSettings via chrome.storage.local
 * 2. Aggregate per-session and lifetime metrics reported by content scripts
 * 3. Relay state between popup ↔ content via chrome.runtime messaging
 * 4. Manage toolbar badge (live event count + status color)
 * 5. Handle keyboard shortcut quick-toggle
 * 6. Maintain real-time activity feed
 *
 * Zero network I/O — all processing is local.
 */

import {
  type VitiateMessage,
  type VitiateSettings,
  type SessionMetrics,
  type LifetimeMetrics,
  type ActivityEntry,
  defaultSettings,
  defaultMetrics,
  defaultLifetimeMetrics,
  formatCompactNumber,
} from "../shared/types";

/* ------------------------------------------------------------------ */
/*  In-memory session metrics (reset each time the SW spins up)       */
/* ------------------------------------------------------------------ */
let sessionMetrics: SessionMetrics = defaultMetrics();

/** Circular buffer for real-time activity feed (last 50 entries) */
const MAX_FEED = 50;
let activityFeed: ActivityEntry[] = [];

/* ------------------------------------------------------------------ */
/*  Settings helpers                                                   */
/* ------------------------------------------------------------------ */

async function loadSettings(): Promise<VitiateSettings> {
  const result = await chrome.storage.local.get("vitiate_settings");
  const stored = result.vitiate_settings as VitiateSettings | undefined;
  if (!stored) return defaultSettings();
  // Ensure new fields have defaults for users upgrading from older versions
  return { ...defaultSettings(), ...stored };
}

async function saveSettings(settings: VitiateSettings): Promise<void> {
  await chrome.storage.local.set({ vitiate_settings: settings });
}

function isDomainEnabled(settings: VitiateSettings, domain?: string): boolean {
  if (!settings.enabled) return false;
  if (!domain) return settings.enabled;
  if (domain in settings.domainOverrides) {
    return settings.domainOverrides[domain];
  }
  return true; // default: on for unknown domains
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
/*  Metrics helpers                                                    */
/* ------------------------------------------------------------------ */

function getTimelineKey(): string {
  // Bucket by minute for the session chart
  const d = new Date();
  return `${d.getHours().toString().padStart(2, "0")}:${d
    .getMinutes()
    .toString()
    .padStart(2, "0")}`;
}

async function applyMetricsDelta(delta: Partial<SessionMetrics>): Promise<void> {
  if (delta.interceptedEvents) {
    sessionMetrics.interceptedEvents += delta.interceptedEvents;
  }
  if (delta.syntheticEventsInjected) {
    sessionMetrics.syntheticEventsInjected += delta.syntheticEventsInjected;
  }
  if (delta.sanitizedInputs) {
    sessionMetrics.sanitizedInputs += delta.sanitizedInputs;
  }
  const key = getTimelineKey();
  if (!sessionMetrics.timeline[key]) {
    sessionMetrics.timeline[key] = { intercepted: 0, poisoned: 0 };
  }
  sessionMetrics.timeline[key].intercepted += delta.interceptedEvents ?? 0;
  sessionMetrics.timeline[key].poisoned += delta.syntheticEventsInjected ?? 0;

  // Persist to lifetime metrics
  const lifetime = await loadLifetimeMetrics();
  lifetime.interceptedEvents += delta.interceptedEvents ?? 0;
  lifetime.syntheticEventsInjected += delta.syntheticEventsInjected ?? 0;
  lifetime.sanitizedInputs += delta.sanitizedInputs ?? 0;
  await saveLifetimeMetrics(lifetime);

  // Update badge
  await updateBadge();
}

/* ------------------------------------------------------------------ */
/*  Toolbar badge                                                      */
/* ------------------------------------------------------------------ */

async function updateBadge(): Promise<void> {
  const settings = await loadSettings();
  if (!settings.enabled) {
    await chrome.action.setBadgeText({ text: "OFF" });
    await chrome.action.setBadgeBackgroundColor({ color: "#6b7280" }); // gray
    return;
  }

  const total = sessionMetrics.interceptedEvents + sessionMetrics.syntheticEventsInjected;
  const text = total === 0 ? "" : formatCompactNumber(total);

  await chrome.action.setBadgeText({ text });
  await chrome.action.setBadgeBackgroundColor({ color: "#34d399" }); // emerald
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
    // Handle async responses
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
    case "GET_SETTINGS": {
      const settings = await loadSettings();
      const domainEnabled = isDomainEnabled(settings, msg.domain);
      sendResponse({ type: "SETTINGS_RESPONSE", settings, domainEnabled });
      break;
    }
    case "UPDATE_SETTINGS": {
      const current = await loadSettings();
      const merged: VitiateSettings = { ...current, ...msg.settings };
      await saveSettings(merged);
      await updateBadge();
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
      for (const entry of msg.entries) {
        activityFeed.push(entry);
      }
      // Keep feed bounded
      if (activityFeed.length > MAX_FEED) {
        activityFeed = activityFeed.slice(-MAX_FEED);
      }
      break;
    }
    case "RESET_METRICS": {
      sessionMetrics = defaultMetrics();
      activityFeed = [];
      await updateBadge();
      break;
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Keyboard shortcut handler (Alt+Shift+V toggle)                     */
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
  }
  await updateBadge();
});
