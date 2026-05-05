/**
 * Vitiate Shared Types  v2
 * Central type definitions shared across background, content, and popup modules.
 *
 * v2 additions:
 * - SCHEMA_VERSION + migrateSettings() for forward-compatible settings upgrades
 * - ModuleId / ModulePolicy: per-module enablement for the defense pipeline
 * - ModuleCounter: per-module observability counters
 * - FingerprintBundle: coherent cross-property fingerprint spoof profile
 * - IncidentEntry: site-compatibility incident logging
 * - HealthStatus / PolicyReason: operational status types
 * - DiagnosticsSnapshot: exportable local debug bundle
 * - Extended IntensityConfig with token-bucket parameters
 * - RISK_TIER_PRESETS: intensity → module policy mapping
 * - Extended VitiateSettings with schemaVersion, modulePolicy, domainModulePolicy
 * - Extended VitiateMessage with v2 message types
 */

export const SCHEMA_VERSION = 2;

// ------------------------------------------------------------------ //
//  Core scalar types                                                  //
// ------------------------------------------------------------------ //

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

/** Defense pipeline module identifiers */
export type ModuleId = "intercept" | "poison" | "fingerprint" | "sanitize";

/** Engine operational health */
export type HealthStatus = "active" | "degraded" | "error" | "disabled";

/** Explanation for why a domain's policy is what it is */
export type PolicyReason =
  | "global-disabled"
  | "domain-disabled"
  | "domain-enabled"
  | "default-enabled";

// ------------------------------------------------------------------ //
//  Module policy                                                      //
// ------------------------------------------------------------------ //

/** Per-module enablement policy for the defense pipeline */
export interface ModulePolicy {
  /** Event interception and timestamp jitter */
  intercept: boolean;
  /** Synthetic event injection */
  poison: boolean;
  /** Canvas / WebGL / Navigator / Screen spoofing */
  fingerprint: boolean;
  /** PII sanitization in forms and paste flows */
  sanitize: boolean;
}

/** Per-module observability counters */
export interface ModuleCounter {
  processed: number;
  errors: number;
  skippedRateLimit: number;
  lastActiveMs: number;
}

// ------------------------------------------------------------------ //
//  Intensity config                                                   //
// ------------------------------------------------------------------ //

/** Intensity configuration parameters (v2 adds token-bucket fields) */
export interface IntensityConfig {
  minSynthetic: number;
  maxSynthetic: number;
  jitterMs: number;
  mouseOffset: number;
  clickOffset: number;
  /** Token-bucket replenish rate (tokens / second) */
  tokenRefillRate: number;
  /** Token-bucket maximum capacity */
  tokenBucketMax: number;
}

/** Map each intensity level to its config */
export const INTENSITY_CONFIGS: Record<IntensityLevel, IntensityConfig> = {
  low:      { minSynthetic: 1,  maxSynthetic: 2,  jitterMs: 5,  mouseOffset: 30,  clickOffset: 10,  tokenRefillRate: 5,  tokenBucketMax: 30  },
  medium:   { minSynthetic: 3,  maxSynthetic: 5,  jitterMs: 15, mouseOffset: 80,  clickOffset: 30,  tokenRefillRate: 15, tokenBucketMax: 60  },
  high:     { minSynthetic: 6,  maxSynthetic: 12, jitterMs: 30, mouseOffset: 150, clickOffset: 60,  tokenRefillRate: 30, tokenBucketMax: 100 },
  paranoid: { minSynthetic: 15, maxSynthetic: 20, jitterMs: 50, mouseOffset: 250, clickOffset: 100, tokenRefillRate: 50, tokenBucketMax: 150 },
};

/**
 * Risk-tier presets: maps each intensity level to a default module policy.
 * "low" disables synthetic poisoning to minimise visible side-effects while
 * keeping fingerprint + sanitization defenses active.
 */
export const RISK_TIER_PRESETS: Record<IntensityLevel, ModulePolicy> = {
  low:      { intercept: true, poison: false, fingerprint: true,  sanitize: true },
  medium:   { intercept: true, poison: true,  fingerprint: true,  sanitize: true },
  high:     { intercept: true, poison: true,  fingerprint: true,  sanitize: true },
  paranoid: { intercept: true, poison: true,  fingerprint: true,  sanitize: true },
};

// ------------------------------------------------------------------ //
//  Fingerprint bundle                                                 //
// ------------------------------------------------------------------ //

/**
 * Coherent cross-property fingerprint bundle.
 * All properties are generated together to ensure internal consistency
 * (e.g. Win32 platform → plausible Windows screen resolutions).
 */
export interface FingerprintBundle {
  platform: string;
  languages: string[];
  hardwareConcurrency: number;
  deviceMemory: number;
  screenWidth: number;
  screenHeight: number;
  colorDepth: number;
  canvasNoiseSeed: number;
}

// ------------------------------------------------------------------ //
//  Metrics                                                            //
// ------------------------------------------------------------------ //

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

// ------------------------------------------------------------------ //
//  Activity feed & incidents                                          //
// ------------------------------------------------------------------ //

/** A single entry in the real-time activity feed */
export interface ActivityEntry {
  /** Timestamp ISO string */
  time: string;
  /** Category icon/type */
  kind: "intercepted" | "poisoned" | "sanitized" | "error";
  /** Short description */
  detail: string;
}

/** Site-compatibility incident record (deduped by domain + module + message) */
export interface IncidentEntry {
  time: string;
  domain: string;
  module: ModuleId;
  message: string;
  /** Occurrence count for deduplication */
  count: number;
}

// ------------------------------------------------------------------ //
//  Settings                                                           //
// ------------------------------------------------------------------ //

/** Persisted user settings (schema v2) */
export interface VitiateSettings {
  /** Schema version — used for forward-compatible migration */
  schemaVersion: number;
  /** Global kill switch */
  enabled: boolean;
  /** Per-domain overrides: domain → enabled */
  domainOverrides: Record<string, boolean>;
  /** Poisoning intensity level */
  intensity: IntensityLevel;
  /** Active module policy (can be customised independently of intensity) */
  modulePolicy: ModulePolicy;
  /** Per-domain module policy overrides */
  domainModulePolicy: Record<string, Partial<ModulePolicy>>;
}

// ------------------------------------------------------------------ //
//  Diagnostics snapshot                                               //
// ------------------------------------------------------------------ //

/** Exportable local debug bundle (zero-network, download-only) */
export interface DiagnosticsSnapshot {
  vitiateVersion: string;
  exportedAt: string;
  schemaVersion: number;
  settings: VitiateSettings;
  sessionMetrics: SessionMetrics;
  lifetimeMetrics: LifetimeMetrics;
  moduleCounters: Record<ModuleId, ModuleCounter>;
  incidents: IncidentEntry[];
  health: HealthStatus;
}

// ------------------------------------------------------------------ //
//  Messages                                                           //
// ------------------------------------------------------------------ //

/** Messages exchanged between content ↔ background ↔ popup */
export type VitiateMessage =
  // ── existing ──────────────────────────────────────────────────────
  | { type: "GET_SETTINGS"; domain?: string }
  | { type: "SETTINGS_RESPONSE"; settings: VitiateSettings; domainEnabled: boolean; policyReason: PolicyReason; effectivePolicy: ModulePolicy }
  | { type: "UPDATE_SETTINGS"; settings: Partial<VitiateSettings> }
  | { type: "TOGGLE_DOMAIN"; domain: string; enabled: boolean }
  | { type: "REMOVE_DOMAIN"; domain: string }
  | { type: "GET_METRICS" }
  | { type: "METRICS_RESPONSE"; metrics: SessionMetrics; lifetime: LifetimeMetrics; feed: ActivityEntry[] }
  | { type: "REPORT_METRICS"; delta: Partial<SessionMetrics> }
  | { type: "REPORT_ACTIVITY"; entries: ActivityEntry[] }
  | { type: "RESET_METRICS" }
  | { type: "GET_ACTIVITY_FEED" }
  | { type: "ACTIVITY_FEED_RESPONSE"; feed: ActivityEntry[] }
  // ── v2: module policy ─────────────────────────────────────────────
  | { type: "UPDATE_MODULE_POLICY"; policy: Partial<ModulePolicy> }
  // ── v2: health ────────────────────────────────────────────────────
  | { type: "GET_HEALTH" }
  | { type: "HEALTH_RESPONSE"; health: HealthStatus; incidents: IncidentEntry[] }
  // ── v2: observability ─────────────────────────────────────────────
  | { type: "REPORT_MODULE_COUNTER"; module: ModuleId; delta: Partial<ModuleCounter> }
  | { type: "REPORT_INCIDENT"; incident: Omit<IncidentEntry, "count"> }
  // ── v2: diagnostics snapshot ──────────────────────────────────────
  | { type: "EXPORT_SNAPSHOT" }
  | { type: "SNAPSHOT_RESPONSE"; snapshot: DiagnosticsSnapshot }
  | { type: "GET_MODULE_COUNTERS" }
  | { type: "MODULE_COUNTERS_RESPONSE"; counters: Record<ModuleId, ModuleCounter> }
  | { type: "ACK" }
  | { type: "ERROR"; message: string };

// ------------------------------------------------------------------ //
//  Factory functions                                                  //
// ------------------------------------------------------------------ //

export function defaultModulePolicy(): ModulePolicy {
  return { intercept: true, poison: true, fingerprint: true, sanitize: true };
}

export function defaultModuleCounter(): ModuleCounter {
  return { processed: 0, errors: 0, skippedRateLimit: 0, lastActiveMs: 0 };
}

export function defaultSettings(): VitiateSettings {
  return {
    schemaVersion: SCHEMA_VERSION,
    enabled: true,
    domainOverrides: {},
    intensity: "medium",
    modulePolicy: defaultModulePolicy(),
    domainModulePolicy: {},
  };
}

export function defaultMetrics(): SessionMetrics {
  return {
    interceptedEvents: 0,
    syntheticEventsInjected: 0,
    sanitizedInputs: 0,
    timeline: {},
  };
}

export function defaultLifetimeMetrics(): LifetimeMetrics {
  return {
    interceptedEvents: 0,
    syntheticEventsInjected: 0,
    sanitizedInputs: 0,
  };
}

// ------------------------------------------------------------------ //
//  Migration                                                          //
// ------------------------------------------------------------------ //

/**
 * Migrate a raw settings object from any prior schema version to the current
 * one.  The function is pure — it never mutates the input.
 */
export function migrateSettings(raw: Record<string, unknown>): VitiateSettings {
  const defaults = defaultSettings();
  const version = (raw.schemaVersion as number | undefined) ?? 1;

  if (version < 2) {
    // v1 → v2: populate modulePolicy from the stored intensity preset
    const intensity = (raw.intensity as IntensityLevel | undefined) ?? "medium";
    return {
      ...defaults,
      enabled: (raw.enabled as boolean | undefined) ?? defaults.enabled,
      domainOverrides: (raw.domainOverrides as Record<string, boolean> | undefined) ?? defaults.domainOverrides,
      intensity,
      modulePolicy: { ...RISK_TIER_PRESETS[intensity] },
    };
  }

  // Same or newer version — merge with defaults to fill any newly-added fields
  return { ...defaults, ...(raw as Partial<VitiateSettings>) };
}

// ------------------------------------------------------------------ //
//  Policy helpers                                                     //
// ------------------------------------------------------------------ //

/** Returns why the given domain's protection policy is in its current state. */
export function getPolicyReason(settings: VitiateSettings, domain?: string): PolicyReason {
  if (!settings.enabled) return "global-disabled";
  if (domain && domain in settings.domainOverrides) {
    return settings.domainOverrides[domain] ? "domain-enabled" : "domain-disabled";
  }
  return "default-enabled";
}

/** Returns the resolved module policy for a domain (base + per-domain override). */
export function getEffectiveModulePolicy(settings: VitiateSettings, domain?: string): ModulePolicy {
  const base = { ...settings.modulePolicy };
  if (domain && settings.domainModulePolicy[domain]) {
    return { ...base, ...settings.domainModulePolicy[domain] };
  }
  return base;
}

/** Returns whether protection is on for a specific domain. */
export function isDomainEnabled(settings: VitiateSettings, domain?: string): boolean {
  if (!settings.enabled) return false;
  if (!domain) return settings.enabled;
  if (domain in settings.domainOverrides) return settings.domainOverrides[domain];
  return true;
}

// ------------------------------------------------------------------ //
//  Formatting                                                         //
// ------------------------------------------------------------------ //

/** Format a number compactly (e.g. 1.2K, 3.4M) */
export function formatCompactNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}
