/**
 * Vitiate — Popup Script
 * Phase 5: User Interface and State Management
 *
 * Communicates with the background service worker to:
 * - Toggle the engine globally / per-domain
 * - Control poisoning intensity
 * - Display session and lifetime metrics
 * - Render an activity chart via Chart.js
 * - Show real-time activity feed
 * - Manage per-domain overrides
 */

import { Chart, type ChartData, registerables } from "chart.js";
import {
  type VitiateMessage,
  type VitiateSettings,
  type SessionMetrics,
  type LifetimeMetrics,
  type ActivityEntry,
  type IntensityLevel,
  formatCompactNumber,
} from "../shared/types";

Chart.register(...registerables);

/* ================================================================== */
/*  DOM references                                                     */
/* ================================================================== */

const header = document.getElementById("header") as HTMLElement;
const shieldIcon = document.getElementById("shield-icon") as HTMLElement;
const globalToggle = document.getElementById("global-toggle") as HTMLInputElement;
const domainToggle = document.getElementById("domain-toggle") as HTMLInputElement;
const domainName = document.getElementById("domain-name") as HTMLElement;

// Session stats
const statIntercepted = document.getElementById("stat-intercepted") as HTMLElement;
const statPoisoned = document.getElementById("stat-poisoned") as HTMLElement;
const statSanitized = document.getElementById("stat-sanitized") as HTMLElement;

// Lifetime stats
const lifetimeIntercepted = document.getElementById("lifetime-intercepted") as HTMLElement;
const lifetimePoisoned = document.getElementById("lifetime-poisoned") as HTMLElement;
const lifetimeSanitized = document.getElementById("lifetime-sanitized") as HTMLElement;

// Sparklines
const sparkIntercepted = document.getElementById("spark-intercepted") as HTMLElement;
const sparkPoisoned = document.getElementById("spark-poisoned") as HTMLElement;
const sparkSanitized = document.getElementById("spark-sanitized") as HTMLElement;

// Intensity
const intensitySlider = document.getElementById("intensity-slider") as HTMLInputElement;
const intensityLabel = document.getElementById("intensity-label") as HTMLElement;

// Activity feed
const feedToggleBtn = document.getElementById("feed-toggle-btn") as HTMLElement;
const feedArrow = document.getElementById("feed-arrow") as HTMLElement;
const feedContainer = document.getElementById("feed-container") as HTMLElement;
const feedList = document.getElementById("feed-list") as HTMLElement;
const feedEmpty = document.getElementById("feed-empty") as HTMLElement;

// Domain management
const domainsToggleBtn = document.getElementById("domains-toggle-btn") as HTMLElement;
const domainsArrow = document.getElementById("domains-arrow") as HTMLElement;
const domainsContainer = document.getElementById("domains-container") as HTMLElement;
const domainsList = document.getElementById("domains-list") as HTMLElement;
const domainsEmpty = document.getElementById("domains-empty") as HTMLElement;

const resetBtn = document.getElementById("reset-btn") as HTMLElement;
const chartCanvas = document.getElementById("activity-chart") as HTMLCanvasElement;

/* ================================================================== */
/*  State                                                              */
/* ================================================================== */

let currentDomain = "";
let settings: VitiateSettings | null = null;

const INTENSITY_LEVELS: IntensityLevel[] = ["low", "medium", "high", "paranoid"];

/** History arrays for sparkline rendering (last 10 data points) */
const sparkHistory = {
  intercepted: [] as number[],
  poisoned: [] as number[],
  sanitized: [] as number[],
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
        grid: { color: "rgba(107,114,128,0.15)" },
      },
      y: {
        beginAtZero: true,
        ticks: { color: "#6b7280", font: { size: 9 } },
        grid: { color: "rgba(107,114,128,0.15)" },
      },
    },
    plugins: {
      legend: {
        labels: { color: "#9ca3af", font: { size: 10 } },
      },
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
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    if (tab?.url) {
      const url = new URL(tab.url);
      currentDomain = url.hostname;
    }
  } catch {
    currentDomain = "";
  }
  domainName.textContent = currentDomain || "—";
}

async function loadSettings(): Promise<void> {
  const response = await send({
    type: "GET_SETTINGS",
    domain: currentDomain,
  });
  if (response?.type === "SETTINGS_RESPONSE") {
    settings = response.settings;
    globalToggle.checked = response.settings.enabled;
    domainToggle.checked = response.domainEnabled;

    // Update shield + header glow state
    updateShieldState(response.settings.enabled);

    // Update intensity slider
    const idx = INTENSITY_LEVELS.indexOf(response.settings.intensity ?? "medium");
    intensitySlider.value = String(idx >= 0 ? idx : 1);
    updateIntensityLabel(response.settings.intensity ?? "medium");

    // Update domain management panel
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

/* ================================================================== */
/*  Rendering                                                          */
/* ================================================================== */

function renderMetrics(metrics: SessionMetrics): void {
  const newIntercepted = metrics.interceptedEvents;
  const newPoisoned = metrics.syntheticEventsInjected;
  const newSanitized = metrics.sanitizedInputs;

  // Animate stat value bump when changed
  animateStatBump(statIntercepted, prevMetrics.intercepted, newIntercepted);
  animateStatBump(statPoisoned, prevMetrics.poisoned, newPoisoned);
  animateStatBump(statSanitized, prevMetrics.sanitized, newSanitized);

  statIntercepted.textContent = formatNumber(newIntercepted);
  statPoisoned.textContent = formatNumber(newPoisoned);
  statSanitized.textContent = formatNumber(newSanitized);

  // Update sparkline history
  updateSparkHistory("intercepted", newIntercepted - prevMetrics.intercepted);
  updateSparkHistory("poisoned", newPoisoned - prevMetrics.poisoned);
  updateSparkHistory("sanitized", newSanitized - prevMetrics.sanitized);
  renderSparkline(sparkIntercepted, sparkHistory.intercepted);
  renderSparkline(sparkPoisoned, sparkHistory.poisoned);
  renderSparkline(sparkSanitized, sparkHistory.sanitized);

  prevMetrics = { intercepted: newIntercepted, poisoned: newPoisoned, sanitized: newSanitized };

  // Update chart
  const labels = Object.keys(metrics.timeline).sort();
  const interceptedData = labels.map((k) => metrics.timeline[k].intercepted);
  const poisonedData = labels.map((k) => metrics.timeline[k].poisoned);

  activityChart.data.labels = labels;
  activityChart.data.datasets[0].data = interceptedData;
  activityChart.data.datasets[1].data = poisonedData;
  activityChart.update();
}

function renderLifetimeMetrics(lifetime: LifetimeMetrics): void {
  lifetimeIntercepted.textContent = formatNumber(lifetime.interceptedEvents);
  lifetimePoisoned.textContent = formatNumber(lifetime.syntheticEventsInjected);
  lifetimeSanitized.textContent = formatNumber(lifetime.sanitizedInputs);
}

const formatNumber = formatCompactNumber;

function formatTime(date: Date): string {
  const h = date.getHours().toString().padStart(2, "0");
  const m = date.getMinutes().toString().padStart(2, "0");
  const s = date.getSeconds().toString().padStart(2, "0");
  return `${h}:${m}:${s}`;
}

/* ================================================================== */
/*  Shield state (Improvement 9)                                       */
/* ================================================================== */

function updateShieldState(enabled: boolean): void {
  const svg = shieldIcon.querySelector(".shield-svg");
  if (svg) {
    svg.classList.toggle("disabled", !enabled);
  }
  header.classList.toggle("disabled", !enabled);
}

/* ================================================================== */
/*  Stat micro-animations (Improvement 10)                             */
/* ================================================================== */

function animateStatBump(el: HTMLElement, oldVal: number, newVal: number): void {
  if (newVal !== oldVal) {
    el.classList.add("bump");
    setTimeout(() => el.classList.remove("bump"), 200);
  }
}

function updateSparkHistory(key: keyof typeof sparkHistory, delta: number): void {
  sparkHistory[key].push(Math.max(0, delta));
  if (sparkHistory[key].length > 10) {
    sparkHistory[key].shift();
  }
}

function renderSparkline(container: HTMLElement, data: number[]): void {
  container.innerHTML = "";
  if (data.length === 0) return;

  const max = Math.max(...data, 1);
  for (const val of data) {
    const bar = document.createElement("div");
    bar.className = "sparkline-bar";
    const h = Math.max(1, Math.round((val / max) * 12));
    bar.style.height = `${h}px`;
    container.appendChild(bar);
  }
}

/* ================================================================== */
/*  Intensity control (Improvement 2)                                  */
/* ================================================================== */

function updateIntensityLabel(level: IntensityLevel): void {
  const labels: Record<IntensityLevel, string> = {
    low: "Low",
    medium: "Medium",
    high: "High",
    paranoid: "Paranoid",
  };
  intensityLabel.textContent = labels[level];
  // Update badge class
  intensityLabel.className = `intensity-badge text-[10px] font-bold uppercase tracking-widest level-${level}`;
}

intensitySlider.addEventListener("input", async () => {
  const level = INTENSITY_LEVELS[Number(intensitySlider.value)] ?? "medium";
  updateIntensityLabel(level);
  await send({
    type: "UPDATE_SETTINGS",
    settings: { intensity: level },
  });
});

/* ================================================================== */
/*  Activity feed (Improvement 7)                                      */
/* ================================================================== */

let feedOpen = false;

feedToggleBtn.addEventListener("click", () => {
  feedOpen = !feedOpen;
  feedContainer.style.display = feedOpen ? "block" : "none";
  feedArrow.classList.toggle("open", feedOpen);
});

function renderActivityFeed(entries: ActivityEntry[]): void {
  if (entries.length === 0) {
    feedEmpty.style.display = "block";
    feedList.innerHTML = "";
    return;
  }
  feedEmpty.style.display = "none";

  // Only re-render if feed content has actually changed
  const latestTime = entries.length > 0 ? entries[entries.length - 1].time : "";
  if (feedList.childElementCount > 0 && feedList.dataset.latestTime === latestTime) return;
  feedList.dataset.latestTime = latestTime;

  feedList.innerHTML = "";
  // Show newest first, limit to last 20
  const recent = entries.slice(-20).reverse();
  for (const entry of recent) {
    const el = document.createElement("div");
    el.className = "feed-entry";

    const iconMap: Record<ActivityEntry["kind"], string> = {
      intercepted: "🛡️",
      poisoned: "☠️",
      sanitized: "🧹",
    };

    const time = new Date(entry.time);
    const timeStr = formatTime(time);

    el.innerHTML = `
      <span class="feed-icon">${iconMap[entry.kind]}</span>
      <span class="feed-time">${timeStr}</span>
      <span class="feed-detail">${escapeHtml(entry.detail)}</span>
    `;
    feedList.appendChild(el);
  }
}

function escapeHtml(str: string): string {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/* ================================================================== */
/*  Domain management (Improvement 6)                                  */
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

  // Attach remove handlers
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
/*  Event handlers                                                     */
/* ================================================================== */

globalToggle.addEventListener("change", async () => {
  await send({
    type: "UPDATE_SETTINGS",
    settings: { enabled: globalToggle.checked },
  });
  updateShieldState(globalToggle.checked);
});

domainToggle.addEventListener("change", async () => {
  if (!currentDomain) return;
  await send({
    type: "TOGGLE_DOMAIN",
    domain: currentDomain,
    enabled: domainToggle.checked,
  });
  // Refresh domain list
  await loadSettings();
});

resetBtn.addEventListener("click", async () => {
  await send({ type: "RESET_METRICS" });
  // Reset local sparkline history
  sparkHistory.intercepted = [];
  sparkHistory.poisoned = [];
  sparkHistory.sanitized = [];
  prevMetrics = { intercepted: 0, poisoned: 0, sanitized: 0 };
  await loadMetrics();
});

/* ================================================================== */
/*  Init                                                               */
/* ================================================================== */

async function init(): Promise<void> {
  await loadCurrentDomain();
  await loadSettings();
  await loadMetrics();

  // Auto-refresh metrics while popup is open
  setInterval(loadMetrics, 3_000);
}

init();
