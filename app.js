const labels = {
  operational: { title: "All monitored systems operational", state: "Operational" },
  degraded: { title: "Some systems are degraded", state: "Degraded" },
  major_outage: { title: "Service outage detected", state: "Outage" },
  unknown: { title: "Current status unavailable", state: "Unknown" },
  outage: { state: "Outage" },
};

const statusSources = [
  "https://46-173-214-4.sslip.io/status.json",
  "status.json",
];

function safeState(value) {
  return ["operational", "degraded", "major_outage", "outage"].includes(value) ? value : "unknown";
}

function renderUnknown(detail) {
  const indicator = document.getElementById("overall-indicator");
  indicator.className = "status-indicator unknown";
  document.getElementById("summary-title").textContent = labels.unknown.title;
  document.getElementById("summary-detail").textContent = detail;
  document.getElementById("component-list").replaceChildren();
}

function renderStatus(status) {
  const generated = new Date(status.generated_at);
  const stale = !Number.isFinite(generated.getTime()) || Date.now() - generated.getTime() > status.max_age_seconds * 1000;
  if (stale) {
    renderUnknown("The latest independent probe result is stale.");
    return;
  }
  const overall = safeState(status.overall_status);
  const indicator = document.getElementById("overall-indicator");
  indicator.className = `status-indicator ${overall}`;
  document.getElementById("summary-title").textContent = (labels[overall] || labels.unknown).title;
  document.getElementById("summary-detail").textContent = "Latest independent control and authenticated network checks completed.";
  const checked = document.getElementById("last-checked");
  checked.dateTime = generated.toISOString();
  checked.textContent = `Checked ${new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(generated)}`;
  document.getElementById("scope-note").textContent = status.data_plane_note;

  const list = document.getElementById("component-list");
  list.replaceChildren();
  for (const component of status.components) {
    const state = safeState(component.status);
    const row = document.createElement("article");
    row.className = "component-row";
    const content = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = component.name;
    const detail = document.createElement("p");
    detail.textContent = component.detail;
    const badge = document.createElement("span");
    badge.className = `component-state ${state}`;
    badge.textContent = (labels[state] || labels.unknown).state;
    content.append(title, detail);
    row.append(content, badge);
    list.append(row);
  }
}

function fetchStatus(source) {
  const separator = source.includes("?") ? "&" : "?";
  return fetch(`${source}${separator}ts=${Date.now()}`, { cache: "no-store" })
    .then((response) => {
      if (!response.ok) throw new Error("status response unavailable");
      return response.json();
    })
    .then((status) => {
      const generated = new Date(status.generated_at);
      const age = Date.now() - generated.getTime();
      const validComponents = Array.isArray(status.components)
        && status.components.length >= 4
        && status.components.every((component) => component
          && typeof component.id === "string"
          && typeof component.name === "string"
          && typeof component.detail === "string"
          && ["operational", "degraded", "outage"].includes(component.status));
      const dataPlaneComponents = validComponents
        ? status.components.filter((component) => component.id === "vpn-data-plane")
        : [];
      if (status.schema_version !== 2
        || !["operational", "degraded", "major_outage"].includes(status.overall_status)
        || !Number.isFinite(generated.getTime())
        || !Number.isInteger(status.max_age_seconds)
        || status.max_age_seconds < 300
        || status.max_age_seconds > 3600
        || age < -300000
        || !validComponents
        || dataPlaneComponents.length !== 1) {
        throw new Error("status response invalid");
      }
      return status;
    });
}

Promise.allSettled(statusSources.map(fetchStatus))
  .then((results) => results
    .filter((result) => result.status === "fulfilled")
    .map((result) => result.value)
    .sort((left, right) => new Date(right.generated_at) - new Date(left.generated_at)))
  .then((statuses) => {
    if (statuses.length === 0) throw new Error("status response unavailable");
    renderStatus(statuses[0]);
  })
  .catch(() => renderUnknown("Unable to load the latest independent probe result."));
