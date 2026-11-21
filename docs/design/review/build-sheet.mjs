// Builds review/index.html (before/after contact sheet) from the captures. node docs/design/review/build-sheet.mjs
import fs from "node:fs";
import path from "node:path";
import {fileURLToPath} from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const surfaces = [
  ["Browser popup · 360 wide", "Eight stacked sections (~1,330 px tall) become one number, three facts and one control (~410 px); the blocked list, rules and settings move to tabs, and Allow 15 min appears only on the selected row.",
    ["popup-light.png", "popup-dark.png"], ["popup-main-light.png", "popup-blocked-light.png", "popup-reduced-dark.png", "popup-rules-light.png", "popup-settings-dark.png", "popup-paused-light.png", "popup-zero-longhost-dark.png", "popup-unsupported-light.png", "popup-blocked-empty-dark.png", "popup-rules-empty-light.png"]],
  ["Threat warning page · 1440 and 390", "A card with an eyebrow and a paragraph becomes one decision on one column edge: Go back is the filled, focused button; Continue takes two steps and names the host.",
    ["warning-1440-light.png", "warning-390-dark.png"], ["warning-1440-light.png", "warning-confirm-1440-dark.png", "warning-390-dark.png", "warning-confirm-390-light.png"]],
  ["Scanner-link interstitial · 1440 and 390", "The question becomes the headline; the scanner path is the primary button; the fine print about popup settings is removed; look-alike names get one callout.",
    ["interstitial-1440-light.png", "interstitial-390-dark.png"], ["interstitial-1440-light.png", "interstitial-390-dark.png", "interstitial-idn-390-light.png", "interstitial-unread-1440-dark.png"]],
  ["Click-to-load placeholder · in the embed's own box", "A dashed box with a paragraph and two link-style buttons becomes a quiet held block: provider as the title, one Load button, one quiet signed-in option.",
    ["placeholder-video-light.png", "placeholder-narrow-dark.png"], ["placeholder-video-light.png", "placeholder-narrow-dark.png", "placeholder-refused-light.png"]],
  ["Web dashboard · 1440 and 390", "Health strip, hero, chart, two breakdowns and a table at equal volume become one answer above the fold (status, blocked today, one-series chart, four reasons) and drill-down tabs.",
    ["dashboard-1440-light.jpg", "dashboard-390-dark.jpg"], ["dashboard-1440-light.png", "dashboard-390-dark.png", "dashboard-reduced-1440-dark.png", "dashboard-empty-390-light.png"]],
  ["KPI scorecard · 1440 and 390", "Two forest hero cards and paragraph-per-KPI become one count off target, three groups, and one aligned line per KPI with a 7-day state strip; evidence moves into each row's disclosure.",
    ["scorecard-1440-light.png", "scorecard-390-dark.png"], ["scorecard-1440-light.png", "scorecard-390-dark.png"]],
  ["Mac menu-bar popover · 340 pt", "The mini Perimeter and one-line layer rows that clipped (\"In 11 of 1…e profiles\") become status, three numbers and two-line layer rows that hold the longest real strings.",
    ["popover-light.png", "popover-dark.png"], ["popover-reduced-light.png", "popover-reduced-dark.png", "popover-unprotected-light.png", "popover-restore-dark.png", "popover-loading-light.png", "popover-protected-dark.png"]],
  ["Mac main window, Overview · 1180 × 760", "A captioned ring graphic competing with three number treatments becomes one focal element, the Path, labelled in place, with three numbers and a one-series day strip below.",
    ["mac-overview-light.png", "mac-overview-dark.png"], ["mac-overview-light.png", "mac-overview-reduced-dark.png", "mac-overview-down-light.png"]],
  ["Mac main window, Activity · 1180 × 760", "Same table, aligned to four column edges, tabular times, hostnames truncated by label, threat rows marked in the threat colour only.",
    ["mac-activity-light.png", "mac-activity-dark.png"], ["mac-activity-light.png", "mac-activity-dark.png"]],
];
const fig = (dir, f) => fs.existsSync(path.join(here, dir, f))
  ? `<figure><a href="${dir}/${f}"><img src="${dir}/${f}" alt="${dir} ${f}" loading="lazy"></a><figcaption>${f.replace(/\.(png|jpg)$/, "")}</figcaption></figure>`
  : (() => { throw new Error("missing " + dir + "/" + f); })();

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Egress Guard: before and after</title>
<link rel="stylesheet" href="../tokens.css">
<style>
  .wrap { max-width: 1440px; margin: 0 auto; padding: var(--s6) var(--s6) var(--s8); }
  header p { color: var(--muted); max-width: 72ch; margin-top: var(--s2); }
  section { margin-top: var(--s7); padding-top: var(--s5); border-top: 1px solid var(--line); }
  section > p { margin-top: var(--s2); max-width: 90ch; }
  .pair { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 2fr); gap: var(--s6); margin-top: var(--s4); align-items: start; }
  .col h3 { font-size: var(--t-body); font-weight: var(--w-strong); color: var(--muted); margin-bottom: var(--s2); }
  .imgs { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: var(--s4); align-items: start; }
  .before .imgs { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
  figure img { display: block; width: 100%; height: auto; box-shadow: 0 0 0 1px var(--line); border-radius: 4px; }
  figcaption { font-size: var(--t-caption); line-height: var(--lh-caption); color: var(--muted); margin-top: var(--s1); }
  @media (max-width: 800px) { .wrap { padding: var(--s5) var(--s4); } .pair { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1 class="t-headline">Egress Guard: before and after</h1>
  <p>Every surface at its real size, light and dark. Rules: <a href="../DESIGN.md">DESIGN.md</a>. Annotated failures: <a href="../do-dont.html">do / don't</a>. Click an image for full size.</p>
</header>
${surfaces.map(([title, note, b, a]) => `<section>
  <h2 class="t-title">${title}</h2>
  <p>${note}</p>
  <div class="pair">
    <div class="col before"><h3>Before (v0.5.0)</h3><div class="imgs">${b.map((f) => fig("before", f)).join("")}</div></div>
    <div class="col after"><h3>After</h3><div class="imgs">${a.map((f) => fig("after", f)).join("")}</div></div>
  </div>
</section>`).join("\n")}
</div>
</body>
</html>
`;
fs.writeFileSync(path.join(here, "index.html"), html);
console.log("wrote index.html");
