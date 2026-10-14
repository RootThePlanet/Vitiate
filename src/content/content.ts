/**
 * Vitiate — Isolated content-script bridge
 *
 * Extension APIs are only available in the isolated world. Page defenses run
 * in page-world.ts (MAIN world) because isolated prototype patches never
 * reach page scripts. This file forwards config in and metrics out.
 * It does not patch DOM APIs.
 */

import {
  PAGE_BRIDGE_CHANNEL,
  type ModuleId,
  type PageWorldConfig,
  type PageWorldReport,
  type VitiateMessage,
} from "../shared/types";
import { extensionApi } from "../shared/extension-api";

const guard = globalThis as { __vitiate_bridge__?: boolean };
if (guard.__vitiate_bridge__) {
  throw new Error("Vitiate bridge already installed");
}
guard.__vitiate_bridge__ = true;

function isReport(data: unknown): data is { channel: string; kind: "report"; report: PageWorldReport } {
  if (!data || typeof data !== "object") return false;
  const record = data as Record<string, unknown>;
  return record.channel === PAGE_BRIDGE_CHANNEL && record.kind === "report" && !!record.report;
}

function pushConfig(config: PageWorldConfig): void {
  window.postMessage({ channel: PAGE_BRIDGE_CHANNEL, kind: "config", config }, "*");
}

async function publishSettings(): Promise<void> {
  try {
    const response = await extensionApi.runtime.sendMessage({
      type: "GET_SETTINGS",
      domain: location.hostname,
    } satisfies VitiateMessage) as VitiateMessage;
    if (response?.type !== "SETTINGS_RESPONSE") return;
    const config: PageWorldConfig = {
      enabled: response.domainEnabled,
      intensity: response.settings.intensity ?? "medium",
      policy: response.effectivePolicy,
      tokenRefillRate: response.settings.customTokenRefillRate,
      tokenBucketMax: response.settings.customTokenBucketMax,
      customSanitizationRules: response.settings.customSanitizationRules ?? [],
    };
    pushConfig(config);
  } catch {
    // Extension context invalidated, or first-run before the worker is ready.
  }
}

function forwardReport(report: PageWorldReport): void {
  if (report.intercepted > 0) {
    report.activity.push({
      time: new Date().toISOString(),
      kind: "intercepted",
      detail: `${report.intercepted} events intercepted`,
    });
  }
  if (report.synthetic > 0) {
    report.activity.push({
      time: new Date().toISOString(),
      kind: "poisoned",
      detail: `${report.synthetic} synthetic pointer events injected`,
    });
  }
  if (report.intercepted > 0 || report.synthetic > 0 || report.sanitized > 0) {
    extensionApi.runtime.sendMessage({
      type: "REPORT_METRICS",
      delta: {
        interceptedEvents: report.intercepted,
        syntheticEventsInjected: report.synthetic,
        sanitizedInputs: report.sanitized,
      },
    } satisfies VitiateMessage).catch(() => {});
  }
  if (report.activity.length > 0) {
    extensionApi.runtime.sendMessage({
      type: "REPORT_ACTIVITY",
      entries: report.activity,
    } satisfies VitiateMessage).catch(() => {});
  }
  for (const moduleId of Object.keys(report.counters) as ModuleId[]) {
    const delta = report.counters[moduleId];
    if (!delta) continue;
    extensionApi.runtime.sendMessage({
      type: "REPORT_MODULE_COUNTER",
      module: moduleId,
      delta,
    } satisfies VitiateMessage).catch(() => {});
  }
  for (const incident of report.incidents) {
    extensionApi.runtime.sendMessage({
      type: "REPORT_INCIDENT",
      incident: {
        time: new Date().toISOString(),
        domain: location.hostname,
        module: incident.module,
        message: incident.message,
      },
    } satisfies VitiateMessage).catch(() => {});
  }
}

window.addEventListener("message", (ev: MessageEvent) => {
  if (ev.source !== window || !isReport(ev.data)) return;
  forwardReport(ev.data.report);
});

extensionApi.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.vitiate_settings) void publishSettings();
});

void publishSettings();
