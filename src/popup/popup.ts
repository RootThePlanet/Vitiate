/**
 * Vitiate — Popup Script  v2
 *
 * Communicates with the background service worker to:
 * - Toggle the engine globally / per-domain
 * - Control poisoning intensity + per-module enablement
 * - Apply quick preset bundles (intensity + module policy together)
 * - Display health status (active / degraded / error / disabled)
 * - Show policy reason for the current domain
 * - Display session and lifetime metrics + sparklines
 * - Render a live activity chart via Chart.js
 * - Show real-time activity feed
 * - Manage per-domain overrides
 * - Show per-module diagnostic counters + recent incidents
 * - Export a local diagnostics snapshot (JSON download, zero network)
 */

import { Chart, type ChartData, registerables } from "chart.js";
import {
  type VitiateMessage,
  type VitiateSettings,
  type SessionMetrics,
  type LifetimeMetrics,
  type ActivityEntry,
  type IntensityLevel,
  type ModulePolicy,
  type ModuleCounter,
  type ModuleId,
  type HealthStatus,
  type PolicyReason,
  type IncidentEntry,
  type DiagnosticsSnapshot,
  formatCompactNumber,
  RISK_TIER_PRESETS,
} from "../shared/types";

Chart.register(...registerables);

/* ================================================================== */
/*  DOM references                                                     */
/* ================================================================== */

const header      = document.getElementById("header")      as HTMLElement;
const shieldIcon  = document.getElementById("shield-icon") as HTMLElement;
const globalToggle = document.getElementById("global-toggle") as HTMLInputElement;
const domainToggle = document.getElementById("domain-toggle") as HTMLInputElement;
const domainName   = document.getElementById("domain-name")   as HTMLElement;
const policyReason = document.getElementById("policy-reason") as HTMLElement;

// Health
const healthDot  = document.getElementById("health-dot")  as HTMLElement;
const healthText = document.getElementById("health-text") as HTMLElement;

// Session stats
const statIntercepted = document.getElementById("stat-intercepted") as HTMLElement;
const statPoisoned    = document.getElementById("stat-poisoned")    as HTMLElement;
const statSanitized   = document.getElementById("stat-sanitized")   as HTMLElement;

// Lifetime stats
const lifetimeIntercepted = document.getElementById("lifetime-intercepted") as HTMLElement;
const lifetimePoisoned    = document.getElementById("lifetime-poisoned")    as HTMLElement;
const lifetimeSanitized   = document.getElementById("lifetime-sanitized")   as HTMLElement;

// Sparklines
const sparkIntercepted = document.getElementById("spark-intercepted") as HTMLElement;
const sparkPoisoned    = document.getElementById("spark-poisoned")    as HTMLElement;
const sparkSanitized   = document.getElementById("spark-sanitized")   as HTMLElement;

// Intensity
const intensitySlider = document.getElementById("intensity-slider") as HTMLInputElement;
const intensityLabel  = document.getElementById("intensity-label")  as HTMLElement;

// Module controls
const modIntercept   = document.getElementById("mod-intercept")   as HTMLInputElement;
const modPoison      = document.getElementById("mod-poison")      as HTMLInputElement;
const modFingerprint = document.getElementById("mod-fingerprint") as HTMLInputElement;
const modSanitize    = document.getElementById("mod-sanitize")    as HTMLInputElement;
const dotIntercept   = document.getElementById("dot-intercept")   as HTMLElement;
const dotPoison      = document.getElementById("dot-poison")      as HTMLElement;
const dotFingerprint = document.getElementById("dot-fingerprint") as HTMLElement;
const dotSanitize    = document.getElementById("dot-sanitize")    as HTMLElement;

// Preset buttons
const presetBtns = document.querySelectorAll<HTMLButtonElement>(".preset-btn");

// Activity feed
const feedToggleBtn = document.getElementById("feed-toggle-btn") as HTMLElement;
const feedArrow     = document.getElementById("feed-arrow")     as HTMLElement;
const feedContainer = document.getElementById("feed-container") as HTMLElement;
const feedList      = document.getElementById("feed-list")      as HTMLElement;
const feedEmpty     = document.getElementById("feed-empty")     as HTMLElement;

// Domain management
const domainsToggleBtn = document.getElementById("domains-toggle-btn") as HTMLElement;
const domainsArrow     = document.getElementById("domains-arrow")      as HTMLElement;
const domainsContainer = document.getElementById("domains-container")  as HTMLElement;
const domainsList      = document.getElementById("domains-list")       as HTMLElement;
const domainsEmpty     = document.getElementById("domains-empty")      as HTMLElement;

// Diagnostics
const diagToggleBtn  = document.getElementById("diag-toggle-btn")  as HTMLElement;
const diagArrow      = document.getElementById("diag-arrow")       as HTMLElement;
const diagContainer  = document.getElementById("diag-container")   as HTMLElement;
const moduleCountersEl = document.getElementById("module-counters") as HTMLElement;
const incidentsListEl  = document.getElementById("incidents-list")  as HTMLElement;
const diagEmpty        = document.getElementById("diag-empty")      as HTMLElement;

const resetBtn  = document.getElementById("reset-btn")  as HTMLElement;
const exportBtn = document.getElementById("export-btn") as HTMLElement;
const chartCanvas = document.getElementById("activity-chart") as HTMLCanvasElement;

/* ================================================================== */
/*  State                                                              */
/* ================================================================== */

let currentDomain = "";
let settings: VitiateSettings | null = null;

const INTENSITY_LEVELS: IntensityLevel[] = ["low", "medium", "high", "paranoid"];

const sparkHistory = {
  intercepted: [] as number[],
  poisoned:    [] as number[],
  sanitized:   [] as number[],
};
let prevMetrics = { intercepted: 0, poisoned: 0, sanitized: 0 };

/* ================================================================== */
/*  Chart setup                                                        */
/* ================================================================== */

const chartData: ChartData<"line", number[], string> = {
  labels: [],
  datasets: [
    {
      label: "Intercepted",
      data: [],
      borderColor: "#34d399",
      backgroundColor: "rgba(52,211,153,0.1)",
      fill: true,
      tension: 0.4,
      pointRadius: 0,
      borderWidth: 2,
    },
    {
      label: "Poisoned",
      data: [],
      borderColor: "#fbbf24",
      backgroundColor: "rgba(251,191,36,0.1)",
      fill: true,
      tension: 0.4,
      pointRadius: 0,
      borderWidth: 2,
    },
  ],
};

const activityChart = new Chart(chartCanvas, {
  type: "line",
  data: chartData,
  options: {
    responsive: false,
    animation: false,
    scales: {
      x: {
        ticks: { color: "#6b7280", font: { size: 9 } },
        grid:  { color: "rgba(107,114,128,0.15)" },
      },
      y: {
        beginAtZero: true,
        ticks: { color: "#6b7280", font: { size: 9 } },
        grid:  { color: "rgba(107,114,128,0.15)" },
      },
    },
    plugins: {
      legend: { labels: { color: "#9ca3af", font: { size: 10 } } },
    },
  },
});

/* ================================================================== */
/*  Messaging helpers                                                  */
/* ================================================================== */

function send(msg: VitiateMessage): Promise<VitiateMessage> {
  return chrome.runtime.sendMessage(msg);
}

/* ================================================================== */
/*  Data loading                                                       */
/* ================================================================== */

async function loadCurrentDomain(): Promise<void> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      currentDomain = new URL(tab.url).hostname;
    }
  } catch {
    currentDomain = "";
  }
  domainName.textContent = currentDomain || "—";
}

async function loadSettings(): Promise<void> {
  const response = await send({ type: "GET_SETTINGS", domain: currentDomain });
  if (response?.type === "SETTINGS_RESPONSE") {
    settings = response.settings;

    globalToggle.checked = response.settings.enabled;
    domainToggle.checked = response.domainEnabled;

    updateShieldState(response.settings.enabled);
    updatePolicyReason(response.policyReason);

    // Intensity slider
    const idx = INTENSITY_LEVELS.indexOf(response.settings.intensity ?? "medium");
    intensitySlider.value = String(idx >= 0 ? idx : 1);
    updateIntensityLabel(response.settings.intensity ?? "medium");

    // Module toggles
    renderModulePolicy(response.settings.modulePolicy);
    updateActivePreset(response.settings.intensity);

    // Domain list
    renderDomainList(response.settings.domainOverrides);
  }
}

async function loadMetrics(): Promise<void> {
  const response = await send({ type: "GET_METRICS" });
  if (response?.type === "METRICS_RESPONSE") {
    renderMetrics(response.metrics);
    renderLifetimeMetrics(response.lifetime);
    renderActivityFeed(response.feed);
  }
}

async function loadHealth(): Promise<void> {
  const response = await send({ type: "GET_HEALTH" });
  if (response?.type === "HEALTH_RESPONSE") {
    renderHealth(response.health);
    renderIncidents(response.incidents);
  }
}

async function loadModuleCounters(): Promise<void> {
  const response = await send({ type: "GET_MODULE_COUNTERS" });
  if (response?.type === "MODULE_COUNTERS_RESPONSE") {
    renderModuleCounters(response.counters);
  }
}

/* ================================================================== */
/*  Health rendering                                                   */
/* ================================================================== */

const HEALTH_LABELS: Record<HealthStatus, string> = {
  active:   "Active",
  degraded: "Degraded",
  error:    "Error",
  disabled: "Disabled",
};

function renderHealth(health: HealthStatus): void {
  // Remove all health classes
  healthDot.className  = `health-dot health-${health}`;
  healthText.className = `text-[10px] health-text health-${health}`;
  healthText.textContent = HEALTH_LABELS[health];
}

/* ================================================================== */
/*  Policy reason                                                      */
/* ================================================================== */

const REASON_LABELS: Record<PolicyReason, string> = {
  "global-disabled":  "↳ Global protection is off",
  "domain-disabled":  "↳ Disabled for this domain",
  "domain-enabled":   "↳ Explicitly enabled for this domain",
  "default-enabled":  "↳ Protected by default",
};

function updatePolicyReason(reason: PolicyReason): void {
  policyReason.textContent = REASON_LABELS[reason] ?? "";
}

/* ================================================================== */
/*  Module policy controls                                             */
/* ================================================================== */

function renderModulePolicy(policy: ModulePolicy): void {
  modIntercept.checked   = policy.intercept;
  modPoison.checked      = policy.poison;
  modFingerprint.checked = policy.fingerprint;
  modSanitize.checked    = policy.sanitize;

  // Update dot colors
  syncModuleDot(dotIntercept,   policy.intercept);
  syncModuleDot(dotPoison,      policy.poison);
  syncModuleDot(dotFingerprint, policy.fingerprint);
  syncModuleDot(dotSanitize,    policy.sanitize);
}

function syncModuleDot(dot: HTMLElement, enabled: boolean): void {
  if (enabled) {
    dot.style.background   = "#34d399";
    dot.style.boxShadow    = "0 0 4px rgba(52,211,153,0.5)";
  } else {
    dot.style.background   = "#374151";
    dot.style.boxShadow    = "none";
  }
}

function updateActivePreset(level: IntensityLevel): void {
  presetBtns.forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.preset === level);
  });
}

async function applyModuleToggle(key: keyof ModulePolicy, value: boolean): Promise<void> {
  await send({ type: "UPDATE_MODULE_POLICY", policy: { [key]: value } });
  if (settings) {
    settings.modulePolicy[key] = value;
    syncModuleDot(
      key === "intercept"   ? dotIntercept   :
      key === "poison"      ? dotPoison      :
      key === "fingerprint" ? dotFingerprint : dotSanitize,
      value,
    );
  }
}

/* ================================================================== */
/*  Metrics rendering                                                  */
/* ================================================================== */

const formatNumber = formatCompactNumber;

function renderMetrics(metrics: SessionMetrics): void {
  const newIntercepted = metrics.interceptedEvents;
  const newPoisoned    = metrics.syntheticEventsInjected;
  const newSanitized   = metrics.sanitizedInputs;

  animateStatBump(statIntercepted, prevMetrics.intercepted, newIntercepted);
  animateStatBump(statPoisoned,    prevMetrics.poisoned,    newPoisoned);
  animateStatBump(statSanitized,   prevMetrics.sanitized,   newSanitized);

  statIntercepted.textContent = formatNumber(newIntercepted);
  statPoisoned.textContent    = formatNumber(newPoisoned);
  statSanitized.textContent   = formatNumber(newSanitized);

  updateSparkHistory("intercepted", newIntercepted - prevMetrics.intercepted);
  updateSparkHistory("poisoned",    newPoisoned    - prevMetrics.poisoned);
  updateSparkHistory("sanitized",   newSanitized   - prevMetrics.sanitized);
  renderSparkline(sparkIntercepted, sparkHistory.intercepted);
  renderSparkline(sparkPoisoned,    sparkHistory.poisoned);
  renderSparkline(sparkSanitized,   sparkHistory.sanitized);

  prevMetrics = { intercepted: newIntercepted, poisoned: newPoisoned, sanitized: newSanitized };

  // Update chart
  const labels         = Object.keys(metrics.timeline).sort();
  const interceptedData = labels.map((k) => metrics.timeline[k].intercepted);
  const poisonedData    = labels.map((k) => metrics.timeline[k].poisoned);

  activityChart.data.labels           = labels;
  activityChart.data.datasets[0].data = interceptedData;
  activityChart.data.datasets[1].data = poisonedData;
  activityChart.update();
}

function renderLifetimeMetrics(lifetime: LifetimeMetrics): void {
  lifetimeIntercepted.textContent = formatNumber(lifetime.interceptedEvents);
  lifetimePoisoned.textContent    = formatNumber(lifetime.syntheticEventsInjected);
  lifetimeSanitized.textContent   = formatNumber(lifetime.sanitizedInputs);
}

/* ================================================================== */
/*  Shield state                                                       */
/* ================================================================== */

function updateShieldState(enabled: boolean): void {
  const svg = shieldIcon.querySelector(".shield-svg");
  if (svg) svg.classList.toggle("disabled", !enabled);
  header.classList.toggle("disabled", !enabled);
}

/* ================================================================== */
/*  Stat micro-animations                                              */
/* ================================================================== */

function animateStatBump(el: HTMLElement, oldVal: number, newVal: number): void {
  if (newVal !== oldVal) {
    el.classList.add("bump");
    setTimeout(() => el.classList.remove("bump"), 200);
  }
}

function updateSparkHistory(key: keyof typeof sparkHistory, delta: number): void {
  sparkHistory[key].push(Math.max(0, delta));
  if (sparkHistory[key].length > 10) sparkHistory[key].shift();
}

function renderSparkline(container: HTMLElement, data: number[]): void {
  container.innerHTML = "";
  if (data.length === 0) return;
  const max = Math.max(...data, 1);
  for (const val of data) {
    const bar = document.createElement("div");
    bar.className = "sparkline-bar";
    bar.style.height = `${Math.max(1, Math.round((val / max) * 12))}px`;
    container.appendChild(bar);
  }
}

/* ================================================================== */
/*  Intensity control                                                  */
/* ================================================================== */

function updateIntensityLabel(level: IntensityLevel): void {
  const labels: Record<IntensityLevel, string> = {
    low: "Low", medium: "Medium", high: "High", paranoid: "Paranoid",
  };
  intensityLabel.textContent = labels[level];
  intensityLabel.className = `intensity-badge text-[10px] font-bold uppercase tracking-widest level-${level}`;
}

intensitySlider.addEventListener("input", async () => {
  const level = INTENSITY_LEVELS[Number(intensitySlider.value)] ?? "medium";
  updateIntensityLabel(level);
  await send({ type: "UPDATE_SETTINGS", settings: { intensity: level } });
  updateActivePreset(level);
});

/* ================================================================== */
/*  Preset buttons                                                     */
/* ================================================================== */

presetBtns.forEach((btn) => {
  btn.addEventListener("click", async () => {
    const preset = btn.dataset.preset as IntensityLevel | undefined;
    if (!preset) return;

    const idx = INTENSITY_LEVELS.indexOf(preset);
    if (idx < 0) return;

    // Apply intensity
    intensitySlider.value = String(idx);
    updateIntensityLabel(preset);
    await send({ type: "UPDATE_SETTINGS", settings: { intensity: preset } });

    // Apply module policy preset
    const policy = { ...RISK_TIER_PRESETS[preset] };
    await send({ type: "UPDATE_MODULE_POLICY", policy });
    renderModulePolicy(policy);
    updateActivePreset(preset);
  });
});

/* ================================================================== */
/*  Activity feed                                                      */
/* ================================================================== */

let feedOpen = false;

feedToggleBtn.addEventListener("click", () => {
  feedOpen = !feedOpen;
  feedContainer.style.display = feedOpen ? "block" : "none";
  feedArrow.classList.toggle("open", feedOpen);
});

function formatTime(date: Date): string {
  const h = date.getHours().toString().padStart(2, "0");
  const m = date.getMinutes().toString().padStart(2, "0");
  const s = date.getSeconds().toString().padStart(2, "0");
  return `${h}:${m}:${s}`;
}

function renderActivityFeed(entries: ActivityEntry[]): void {
  if (entries.length === 0) {
    feedEmpty.style.display = "block";
    feedList.innerHTML = "";
    return;
  }
  feedEmpty.style.display = "none";

  const latestTime = entries[entries.length - 1].time;
  if (feedList.childElementCount > 0 && feedList.dataset.latestTime === latestTime) return;
  feedList.dataset.latestTime = latestTime;

  feedList.innerHTML = "";
  const recent = entries.slice(-20).reverse();
  for (const entry of recent) {
    const el = document.createElement("div");
    el.className = "feed-entry";

    const iconMap: Record<ActivityEntry["kind"], string> = {
      intercepted: "🛡️",
      poisoned:    "☠️",
      sanitized:   "🧹",
      error:       "⚠️",
    };

    el.innerHTML = `
      <span class="feed-icon">${iconMap[entry.kind]}</span>
      <span class="feed-time">${formatTime(new Date(entry.time))}</span>
      <span class="feed-detail">${escapeHtml(entry.detail)}</span>
    `;
    feedList.appendChild(el);
  }
}

/* ================================================================== */
/*  Domain management                                                  */
/* ================================================================== */

let domainsOpen = false;

domainsToggleBtn.addEventListener("click", () => {
  domainsOpen = !domainsOpen;
  domainsContainer.style.display = domainsOpen ? "block" : "none";
  domainsArrow.classList.toggle("open", domainsOpen);
});

function renderDomainList(overrides: Record<string, boolean>): void {
  const domains = Object.entries(overrides);
  if (domains.length === 0) {
    domainsEmpty.style.display = "block";
    domainsList.innerHTML = "";
    return;
  }
  domainsEmpty.style.display = "none";
  domainsList.innerHTML = "";

  for (const [domain, enabled] of domains.sort(([a], [b]) => a.localeCompare(b))) {
    const row = document.createElement("div");
    row.className = "domain-entry";
    row.innerHTML = `
      <div class="domain-entry-left">
        <span class="domain-entry-status ${enabled ? "enabled" : "disabled"}"></span>
        <span class="domain-entry-name">${escapeHtml(domain)}</span>
      </div>
      <button class="domain-remove-btn" data-domain="${escapeHtml(domain)}" title="Remove override">×</button>
    `;
    domainsList.appendChild(row);
  }

  domainsList.querySelectorAll<HTMLButtonElement>(".domain-remove-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const domain = btn.dataset.domain;
      if (!domain) return;
      await send({ type: "REMOVE_DOMAIN", domain });
      await loadSettings();
    });
  });
}

/* ================================================================== */
/*  Diagnostics panel                                                  */
/* ================================================================== */

let diagOpen = false;

diagToggleBtn.addEventListener("click", () => {
  diagOpen = !diagOpen;
  diagContainer.style.display = diagOpen ? "block" : "none";
  diagArrow.classList.toggle("open", diagOpen);
  if (diagOpen) {
    void loadModuleCounters();
  }
});

const MODULE_NAMES: Record<ModuleId, string> = {
  intercept:   "Intercept",
  poison:      "Poison",
  fingerprint: "Fingerprint",
  sanitize:    "Sanitize",
};

function renderModuleCounters(counters: Record<ModuleId, ModuleCounter>): void {
  moduleCountersEl.innerHTML = "";
  for (const id of Object.keys(counters) as ModuleId[]) {
    const c = counters[id];
    const item = document.createElement("div");
    item.className = "module-counter-item";
    item.innerHTML = `
      <div class="module-counter-name">${escapeHtml(MODULE_NAMES[id])}</div>
      <div class="module-counter-stats">
        <span class="module-counter-ok"   title="Processed">✓ ${formatNumber(c.processed)}</span>
        <span class="module-counter-err"  title="Errors">${c.errors > 0 ? `⚠ ${c.errors}` : ""}</span>
        <span class="module-counter-skip" title="Rate-limited">${c.skippedRateLimit > 0 ? `⏸ ${c.skippedRateLimit}` : ""}</span>
      </div>
    `;
    moduleCountersEl.appendChild(item);
  }
}

function renderIncidents(incidents: IncidentEntry[]): void {
  incidentsListEl.innerHTML = "";
  if (incidents.length === 0) {
    diagEmpty.style.display = "block";
    return;
  }
  diagEmpty.style.display = "none";

  // Show newest first
  for (const inc of [...incidents].reverse().slice(0, 10)) {
    const el = document.createElement("div");
    el.className = "incident-entry";
    el.innerHTML = `
      <div class="incident-header">
        <span class="incident-module">${escapeHtml(inc.module)}</span>
        <span class="incident-domain">${escapeHtml(inc.domain || "—")}</span>
        ${inc.count > 1 ? `<span class="incident-count">×${inc.count}</span>` : ""}
      </div>
      <div class="incident-message">${escapeHtml(inc.message)}</div>
      <div class="incident-time">${formatTime(new Date(inc.time))}</div>
    `;
    incidentsListEl.appendChild(el);
  }
}

/* ================================================================== */
/*  Export snapshot                                                    */
/* ================================================================== */

exportBtn.addEventListener("click", async () => {
  try {
    const response = await send({ type: "EXPORT_SNAPSHOT" });
    if (response?.type !== "SNAPSHOT_RESPONSE") return;

    const snapshot: DiagnosticsSnapshot = response.snapshot;
    const json     = JSON.stringify(snapshot, null, 2);
    const blob     = new Blob([json], { type: "application/json" });
    const url      = URL.createObjectURL(blob);
    const a        = document.createElement("a");
    a.href         = url;
    a.download     = `vitiate-snapshot-${new Date().toISOString().slice(0, 19).replace(/[:]/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch {
    // Silently ignore if snapshot fails
  }
});

/* ================================================================== */
/*  Global event handlers                                              */
/* ================================================================== */

globalToggle.addEventListener("change", async () => {
  await send({ type: "UPDATE_SETTINGS", settings: { enabled: globalToggle.checked } });
  updateShieldState(globalToggle.checked);
});

domainToggle.addEventListener("change", async () => {
  if (!currentDomain) return;
  await send({ type: "TOGGLE_DOMAIN", domain: currentDomain, enabled: domainToggle.checked });
  await loadSettings();
});

// Module toggle handlers
modIntercept.addEventListener("change",   () => applyModuleToggle("intercept",   modIntercept.checked));
modPoison.addEventListener("change",      () => applyModuleToggle("poison",      modPoison.checked));
modFingerprint.addEventListener("change", () => applyModuleToggle("fingerprint", modFingerprint.checked));
modSanitize.addEventListener("change",    () => applyModuleToggle("sanitize",    modSanitize.checked));

resetBtn.addEventListener("click", async () => {
  await send({ type: "RESET_METRICS" });
  sparkHistory.intercepted = [];
  sparkHistory.poisoned    = [];
  sparkHistory.sanitized   = [];
  prevMetrics = { intercepted: 0, poisoned: 0, sanitized: 0 };
  await loadMetrics();
});

/* ================================================================== */
/*  Utilities                                                          */
/* ================================================================== */

function escapeHtml(str: string): string {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/* ================================================================== */
/*  Init                                                               */
/* ================================================================== */

async function init(): Promise<void> {
  await loadCurrentDomain();
  await loadSettings();
  await Promise.all([loadMetrics(), loadHealth()]);

  // Auto-refresh metrics and health while popup is open
  setInterval(loadMetrics, 3_000);
  setInterval(loadHealth,  5_000);
}

init();
