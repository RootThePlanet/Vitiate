(function () {
const SCHEMA_VERSION = 2;
const INTENSITY_CONFIGS = {
  low: { minSynthetic: 1, maxSynthetic: 1, jitterMs: 4, mouseOffset: 24, clickOffset: 8, tokenRefillRate: 5, tokenBucketMax: 30 },
  medium: { minSynthetic: 1, maxSynthetic: 2, jitterMs: 12, mouseOffset: 48, clickOffset: 16, tokenRefillRate: 15, tokenBucketMax: 60 },
  high: { minSynthetic: 1, maxSynthetic: 3, jitterMs: 24, mouseOffset: 80, clickOffset: 24, tokenRefillRate: 30, tokenBucketMax: 100 },
  paranoid: { minSynthetic: 2, maxSynthetic: 4, jitterMs: 40, mouseOffset: 120, clickOffset: 36, tokenRefillRate: 50, tokenBucketMax: 150 }
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
    domainModulePolicy: {},
    customSanitizationRules: []
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
const PAGE_BRIDGE_CHANNEL = "vitiate-bridge-v3";


const globalWithBrowser = globalThis;
const extensionApi = globalWithBrowser.browser ?? chrome;





const guard = globalThis;
if (guard.__vitiate_bridge__) {
  throw new Error("Vitiate bridge already installed");
}
guard.__vitiate_bridge__ = true;
function isReport(data) {
  if (!data || typeof data !== "object") return false;
  const record = data;
  return record.channel === PAGE_BRIDGE_CHANNEL && record.kind === "report" && !!record.report;
}
function pushConfig(config) {
  window.postMessage({ channel: PAGE_BRIDGE_CHANNEL, kind: "config", config }, "*");
}
async function publishSettings() {
  try {
    const response = await extensionApi.runtime.sendMessage({
      type: "GET_SETTINGS",
      domain: location.hostname
    });
    if (response?.type !== "SETTINGS_RESPONSE") return;
    const config = {
      enabled: response.domainEnabled,
      intensity: response.settings.intensity ?? "medium",
      policy: response.effectivePolicy,
      tokenRefillRate: response.settings.customTokenRefillRate,
      tokenBucketMax: response.settings.customTokenBucketMax,
      customSanitizationRules: response.settings.customSanitizationRules ?? []
    };
    pushConfig(config);
  } catch {
  }
}
function forwardReport(report) {
  if (report.intercepted > 0) {
    report.activity.push({
      time: (/* @__PURE__ */ new Date()).toISOString(),
      kind: "intercepted",
      detail: `${report.intercepted} events intercepted`
    });
  }
  if (report.synthetic > 0) {
    report.activity.push({
      time: (/* @__PURE__ */ new Date()).toISOString(),
      kind: "poisoned",
      detail: `${report.synthetic} synthetic pointer events injected`
    });
  }
  if (report.intercepted > 0 || report.synthetic > 0 || report.sanitized > 0) {
    extensionApi.runtime.sendMessage({
      type: "REPORT_METRICS",
      delta: {
        interceptedEvents: report.intercepted,
        syntheticEventsInjected: report.synthetic,
        sanitizedInputs: report.sanitized
      }
    }).catch(() => {
    });
  }
  if (report.activity.length > 0) {
    extensionApi.runtime.sendMessage({
      type: "REPORT_ACTIVITY",
      entries: report.activity
    }).catch(() => {
    });
  }
  for (const moduleId of Object.keys(report.counters)) {
    const delta = report.counters[moduleId];
    if (!delta) continue;
    extensionApi.runtime.sendMessage({
      type: "REPORT_MODULE_COUNTER",
      module: moduleId,
      delta
    }).catch(() => {
    });
  }
  for (const incident of report.incidents) {
    extensionApi.runtime.sendMessage({
      type: "REPORT_INCIDENT",
      incident: {
        time: (/* @__PURE__ */ new Date()).toISOString(),
        domain: location.hostname,
        module: incident.module,
        message: incident.message
      }
    }).catch(() => {
    });
  }
}
window.addEventListener("message", (ev) => {
  if (ev.source !== window || !isReport(ev.data)) return;
  forwardReport(ev.data.report);
});
extensionApi.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.vitiate_settings) void publishSettings();
});
void publishSettings();

})();
