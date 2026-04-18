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

/** Poisoning intensity levels */
export type IntensityLevel = "low" | "medium" | "high" | "paranoid";

/** Intensity configuration parameters */
export interface IntensityConfig {
  minSynthetic: number;
  maxSynthetic: number;
  jitterMs: number;
  mouseOffset: number;
  clickOffset: number;
}

/** Map each intensity level to its config */
export const INTENSITY_CONFIGS: Record<IntensityLevel, IntensityConfig> = {
  low:      { minSynthetic: 1,  maxSynthetic: 2,  jitterMs: 5,  mouseOffset: 30,  clickOffset: 10 },
  medium:   { minSynthetic: 3,  maxSynthetic: 5,  jitterMs: 15, mouseOffset: 80,  clickOffset: 30 },
  high:     { minSynthetic: 6,  maxSynthetic: 12, jitterMs: 30, mouseOffset: 150, clickOffset: 60 },
  paranoid: { minSynthetic: 15, maxSynthetic: 20, jitterMs: 50, mouseOffset: 250, clickOffset: 100 },
};

/** Per-session metrics for the popup dashboard */
export interface SessionMetrics {
  interceptedEvents: number;
  syntheticEventsInjected: number;
  sanitizedInputs: number;
  /** Timestamp-keyed counters for chart rendering */
  timeline: Record<string, { intercepted: number; poisoned: number }>;
}

/** Lifetime (all-time) cumulative metrics persisted to storage */
export interface LifetimeMetrics {
  interceptedEvents: number;
  syntheticEventsInjected: number;
  sanitizedInputs: number;
}

/** A single entry in the real-time activity feed */
export interface ActivityEntry {
  /** Timestamp ISO string */
  time: string;
  /** Category icon/type */
  kind: "intercepted" | "poisoned" | "sanitized";
  /** Short description */
  detail: string;
}

/** Persisted user settings */
export interface VitiateSettings {
  /** Global kill switch */
  enabled: boolean;
  /** Per-domain overrides: domain → enabled */
  domainOverrides: Record<string, boolean>;
  /** Poisoning intensity level */
  intensity: IntensityLevel;
}

/** Messages exchanged between content ↔ background ↔ popup */
export type VitiateMessage =
  | { type: "GET_SETTINGS"; domain?: string }
  | { type: "SETTINGS_RESPONSE"; settings: VitiateSettings; domainEnabled: boolean }
  | { type: "UPDATE_SETTINGS"; settings: Partial<VitiateSettings> }
  | { type: "TOGGLE_DOMAIN"; domain: string; enabled: boolean }
  | { type: "REMOVE_DOMAIN"; domain: string }
  | { type: "GET_METRICS" }
  | { type: "METRICS_RESPONSE"; metrics: SessionMetrics; lifetime: LifetimeMetrics; feed: ActivityEntry[] }
  | { type: "REPORT_METRICS"; delta: Partial<SessionMetrics> }
  | { type: "REPORT_ACTIVITY"; entries: ActivityEntry[] }
  | { type: "RESET_METRICS" }
  | { type: "GET_ACTIVITY_FEED" }
  | { type: "ACTIVITY_FEED_RESPONSE"; feed: ActivityEntry[] };

/** Default settings factory */
export function defaultSettings(): VitiateSettings {
  return {
    enabled: true,
    domainOverrides: {},
    intensity: "medium",
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

/** Default lifetime metrics factory */
export function defaultLifetimeMetrics(): LifetimeMetrics {
  return {
    interceptedEvents: 0,
    syntheticEventsInjected: 0,
    sanitizedInputs: 0,
  };
}

/** Format a number compactly (e.g. 1.2K, 3.4M) */
export function formatCompactNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}
