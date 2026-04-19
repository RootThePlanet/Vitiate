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

export { INTENSITY_CONFIGS as I, RISK_TIER_PRESETS as R, SCHEMA_VERSION as S, defaultModuleCounter as a, getEffectiveModulePolicy as b, defaultSettings as c, defaultMetrics as d, defaultLifetimeMetrics as e, formatCompactNumber as f, getPolicyReason as g, isDomainEnabled as i, migrateSettings as m };
