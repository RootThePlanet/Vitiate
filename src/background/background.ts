/**
 * Vitiate — Background Service Worker (Manifest V3)
 *
 * Responsibilities:
 * 1. Persist and serve VitiateSettings via chrome.storage.local
 * 2. Aggregate per-session metrics reported by content scripts
 * 3. Relay state between popup ↔ content via chrome.runtime messaging
 *
 * Zero network I/O — all processing is local.
 */

import {
  type VitiateMessage,
  type VitiateSettings,
  type SessionMetrics,
  defaultSettings,
  defaultMetrics,
} from "../shared/types";

/* ------------------------------------------------------------------ */
/*  In-memory session metrics (reset each time the SW spins up)       */
/* ------------------------------------------------------------------ */
let sessionMetrics: SessionMetrics = defaultMetrics();

/* ------------------------------------------------------------------ */
/*  Settings helpers                                                   */
/* ------------------------------------------------------------------ */

async function loadSettings(): Promise<VitiateSettings> {
  const result = await chrome.storage.local.get("vitiate_settings");
  return (result.vitiate_settings as VitiateSettings) ?? defaultSettings();
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

function applyMetricsDelta(delta: Partial<SessionMetrics>): void {
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
  sender: chrome.runtime.MessageSender,
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
      break;
    }
    case "TOGGLE_DOMAIN": {
      const settings = await loadSettings();
      settings.domainOverrides[msg.domain] = msg.enabled;
      await saveSettings(settings);
      break;
    }
    case "GET_METRICS": {
      sendResponse({ type: "METRICS_RESPONSE", metrics: sessionMetrics });
      break;
    }
    case "REPORT_METRICS": {
      applyMetricsDelta(msg.delta);
      break;
    }
    case "RESET_METRICS": {
      sessionMetrics = defaultMetrics();
      break;
    }
  }
}

/* ------------------------------------------------------------------ */
/*  Extension lifecycle                                                */
/* ------------------------------------------------------------------ */

chrome.runtime.onInstalled.addListener(async () => {
  const existing = await chrome.storage.local.get("vitiate_settings");
  if (!existing.vitiate_settings) {
    await saveSettings(defaultSettings());
  }
});
