// Fixture page script: one session XHR (must load) and one same-origin analytics beacon (should be blocked).
(function () {
  "use strict";
  const report = (id, text) => { const node = document.getElementById(id); if (node) node.textContent = text; };
  const status = document.createElement("p");
  status.id = "fixture-status";
  document.body.append(status);
  fetch("/api/session", {credentials: "same-origin"})
    .then((r) => r.text()).then((t) => report("fixture-status", `session:${t}`))
    .catch(() => report("fixture-status", "session:failed"));
  const queued = navigator.sendBeacon("/collect", JSON.stringify({event: "pageview"}));
  document.body.dataset.beaconQueued = String(queued);
})();
