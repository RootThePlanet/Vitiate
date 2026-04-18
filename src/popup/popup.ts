/**
 * Vitiate — Popup Script
 * Phase 5: User Interface and State Management
 *
 * Communicates with the background service worker to:
 * - Toggle the engine globally / per-domain
 * - Display session metrics
 * - Render an activity chart via Chart.js
 */

import { Chart, type ChartData, registerables } from "chart.js";
import type { VitiateMessage, VitiateSettings, SessionMetrics } from "../shared/types";

Chart.register(...registerables);

/* ================================================================== */
/*  DOM references                                                     */
/* ================================================================== */

const globalToggle = document.getElementById("global-toggle") as HTMLInputElement;
const domainToggle = document.getElementById("domain-toggle") as HTMLInputElement;
const domainName = document.getElementById("domain-name") as HTMLElement;
const statIntercepted = document.getElementById("stat-intercepted") as HTMLElement;
const statPoisoned = document.getElementById("stat-poisoned") as HTMLElement;
const statSanitized = document.getElementById("stat-sanitized") as HTMLElement;
const resetBtn = document.getElementById("reset-btn") as HTMLElement;
const chartCanvas = document.getElementById("activity-chart") as HTMLCanvasElement;

/* ================================================================== */
/*  State                                                              */
/* ================================================================== */

let currentDomain = "";
let settings: VitiateSettings | null = null;

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
  }
}

async function loadMetrics(): Promise<void> {
  const response = await send({ type: "GET_METRICS" });
  if (response?.type === "METRICS_RESPONSE") {
    renderMetrics(response.metrics);
  }
}

function renderMetrics(metrics: SessionMetrics): void {
  statIntercepted.textContent = formatNumber(metrics.interceptedEvents);
  statPoisoned.textContent = formatNumber(metrics.syntheticEventsInjected);
  statSanitized.textContent = formatNumber(metrics.sanitizedInputs);

  // Update chart
  const labels = Object.keys(metrics.timeline).sort();
  const interceptedData = labels.map((k) => metrics.timeline[k].intercepted);
  const poisonedData = labels.map((k) => metrics.timeline[k].poisoned);

  activityChart.data.labels = labels;
  activityChart.data.datasets[0].data = interceptedData;
  activityChart.data.datasets[1].data = poisonedData;
  activityChart.update();
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

/* ================================================================== */
/*  Event handlers                                                     */
/* ================================================================== */

globalToggle.addEventListener("change", async () => {
  await send({
    type: "UPDATE_SETTINGS",
    settings: { enabled: globalToggle.checked },
  });
});

domainToggle.addEventListener("change", async () => {
  if (!currentDomain) return;
  await send({
    type: "TOGGLE_DOMAIN",
    domain: currentDomain,
    enabled: domainToggle.checked,
  });
});

resetBtn.addEventListener("click", async () => {
  await send({ type: "RESET_METRICS" });
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
