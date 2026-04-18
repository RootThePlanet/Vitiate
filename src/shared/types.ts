/**
 * Vitiate Shared Types
 * Central type definitions shared across background, content, and popup modules.
 */

/** Tracked behavioral event categories */
export type TrackedEventType =
  | "mousemove"
  | "click"
  | "keydown"
  | "keyup"
  | "scroll"
  | "submit";

/** Per-session metrics for the popup dashboard */
export interface SessionMetrics {
  interceptedEvents: number;
  syntheticEventsInjected: number;
  sanitizedInputs: number;
  /** Timestamp-keyed counters for chart rendering */
  timeline: Record<string, { intercepted: number; poisoned: number }>;
}

/** Persisted user settings */
export interface VitiateSettings {
  /** Global kill switch */
  enabled: boolean;
  /** Per-domain overrides: domain → enabled */
  domainOverrides: Record<string, boolean>;
}

/** Messages exchanged between content ↔ background ↔ popup */
export type VitiateMessage =
  | { type: "GET_SETTINGS"; domain?: string }
  | { type: "SETTINGS_RESPONSE"; settings: VitiateSettings; domainEnabled: boolean }
  | { type: "UPDATE_SETTINGS"; settings: Partial<VitiateSettings> }
  | { type: "TOGGLE_DOMAIN"; domain: string; enabled: boolean }
  | { type: "GET_METRICS" }
  | { type: "METRICS_RESPONSE"; metrics: SessionMetrics }
  | { type: "REPORT_METRICS"; delta: Partial<SessionMetrics> }
  | { type: "RESET_METRICS" };

/** Default settings factory */
export function defaultSettings(): VitiateSettings {
  return {
    enabled: true,
    domainOverrides: {},
  };
}

/** Default metrics factory */
export function defaultMetrics(): SessionMetrics {
  return {
    interceptedEvents: 0,
    syntheticEventsInjected: 0,
    sanitizedInputs: 0,
    timeline: {},
  };
}
