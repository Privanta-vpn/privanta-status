const labels = {
  operational: { title: "All monitored systems operational", state: "Operational" },
  degraded: { title: "Some systems are degraded", state: "Degraded" },
  major_outage: { title: "Service outage detected", state: "Outage" },
  unknown: { title: "Current status unavailable", state: "Unknown" },
  outage: { state: "Outage" },
};

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
  document.getElementById("summary-detail").textContent = "Latest independent synthetic checks completed.";
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

fetch(`status.json?ts=${Date.now()}`, { cache: "no-store" })
  .then((response) => {
    if (!response.ok) throw new Error("status response unavailable");
    return response.json();
  })
  .then(renderStatus)
  .catch(() => renderUnknown("Unable to load the latest independent probe result."));
