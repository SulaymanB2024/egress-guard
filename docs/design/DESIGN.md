# Egress Guard design system

One system for every surface: the Chrome extension popup, the extension's full pages (threat warning, scanner-link interstitial, click-to-load placeholder), the web dashboard, the KPI scorecard and the native Mac app. Every rule below can be checked by measurement or by a yes/no question. If a rule and a mockup disagree, the rule wins and the mockup is a bug.

| File | What it is |
|---|---|
| [`tokens.css`](tokens.css) | The tokens and base components. Implementers adopt this file as-is for every web surface; the SwiftUI app mirrors its values (section 15). |
| [`mockups/`](mockups/) | High-fidelity static specs, light and dark, with real and awkward fixture strings and the empty, degraded and threat states. Open any file in a browser; `#hash` switches page states. |
| [`review/index.html`](review/index.html) | Before/after contact sheet at real sizes. |
| [`review/capture.mjs`](review/capture.mjs) | Headless capture plus the measured audit (clipping, type sizes, off-scale spacing, primary-button count). `node docs/design/review/capture.mjs` |
| [`do-dont.html`](do-dont.html) | Annotated crops of the current UI against the redesigned equivalent. |

---

## 1. Principles

Five, each with the test that decides it.

1. **One answer first.** Each view answers one question, and the answer is the single largest thing on it.
   *Test:* the largest font size on the view is used by exactly one element, and that element is the answer (popup: blocked on this page; dashboard: blocked today; scorecard: KPIs off target; Mac Overview: the Path; warning page: the headline).
2. **Colour means state.** Hue appears only to say protected, reduced, unprotected or threat. Everything else is ink on paper.
   *Test:* render the view in greyscale. The only information lost is state, and every coloured pixel maps to one of the five states in section 4. No coloured headings, blocks or bars that are not state.
3. **Space before lines.** Hierarchy comes from size, weight and spacing. A line separates rows of one repeating list, or a fixed region (toolbar, tab bar). Nothing else gets a border.
   *Test:* no box inside a box; no card around a single metric; every visible line is either a list hairline, a tab/toolbar edge or a control boundary.
4. **Whole and unexplained.** Every string appears whole at its longest real length or is truncated by the rules in section 8, and nothing needs a caption to be understood.
   *Test:* the audit in `capture.mjs` reports zero clipped elements; no text on the view tells the reader how to read the view ("Rings are…", "Ticks show…", a legend for a single series).
5. **Safe is easy.** The safe action is the one filled button. There is at most one filled button per view. Risky actions are secondary or quiet and take a second step.
   *Test:* count `.btn.primary` per view (audit column `P`): 0 or 1, and when 1 it is the safe or resuming action (Go back, Continue through the scanner, Resume protection, Cancel).

---

## 2. Layout

### Spacing scale
`4 · 8 · 12 · 16 · 24 · 32 · 48 · 64` px (pt on macOS), tokens `--s1`…`--s8`. Every padding, margin and gap is one of these. Allowed exceptions, each named: 1px hairlines; 2px segmented-control track inset; a value derived from a grid column so that two edges coincide (for example the scorecard evidence indent = state column 128 + gap 24); the decision pages' optical top offset, derived from the viewport height (see "Decision pages", marked `data-optical`). The audit lists any other value.

Vertical rhythm inside a block uses 4/8; between blocks uses 24/32; between sections 48.

### Grids and alignment edges

| Surface | Size | Grid | Alignment edges |
|---|---|---|---|
| Popup | 360 wide; height follows content, budget 520 | One 328 column, 16 gutters | Left 16, right 344. Header, tabs, focal number, metric row and segmented control all start at 16. Metric row is three equal columns (99.3 each, 16 gap). |
| Warning and interstitial | Any; specs at 1440 and 390 | One 560 column, centred; brand bar on the same column | Column left edge is the only left edge: brand mark, state line, headline, host, facts and the primary button share it. At ≤480 the column is the viewport minus 16 gutters and buttons go full width. |
| Embed placeholder | The embed's own box (min 120 tall) | 16 inset | Content top-left at 16,16 is vertically centred in the box; never centred horizontally (the page around it is left-aligned text). |
| Dashboard | 1440 and 390 | 12 columns, max 1152 content, 24 gutters, 32 margins; one column ≤720 with 16 margins | Focal metric spans columns 1–4, chart 5–12; their bottoms share the axis baseline. Activity table columns 88 / flexible / 240 / 88. |
| Scorecard | 1440 and 390 | Same container as the dashboard | KPI row columns: state 128, name flexible, value 128 right-aligned, target 232, 7-day 112. The value's right edge is one vertical line through all eleven rows. |
| Mac popover | 340 pt wide | 16 pt insets, one 308 column | Status dot, numbers, layer dots and menu text all at x = 16. Menu highlight is inset 4, text at 16. |
| Mac window | min 980 × 660, spec at 1180 × 760 | Sidebar 200; content insets 32 | Content left edge 232 (window coordinates) carries status, Path start, metric row and chart. |

### Line length
Body prose ≤ 72 characters (`max-width: 72ch`). Decision pages ≤ 560 px column (≈ 65 characters at 14 px). Table rows may be wider; any prose cell inside them is one line and truncates by section 8.

---

## 3. Type

One scale, five sizes, two weights (400 and 600). Use the role classes (`.t-display`, `.t-headline`, `.t-title`, `.t-body`, `.t-caption`), never raw sizes.

| Role | Web (system UI stack) | macOS (SF Pro) | Used for |
|---|---|---|---|
| Display | 48 / 48, 600, tabular | 44 / 44, semibold | The one focal number per view. Never words, except the headline of a decision page (see "Decision pages"). |
| Headline | 24 / 30, 600 | 22 / 28, semibold | Page or state headline; secondary metric values on wide views. |
| Title | 16 / 22, 600 | 15 / 20, semibold | Section titles; metric values in compact rows; empty-state titles. |
| Body | 14 / 20, 400 or 600 | 13 / 17 | Everything else. |
| Caption | 12 / 16, 400 | 11 / 14 | Metric labels in compact rows, secondary row lines, axis labels, timestamps. Never body prose longer than one line. |

- Web stack: `-apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif`. Mono: `ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace`. No web fonts.
- Letter-spacing: −0.02em on display, −0.01em on headline, 0 elsewhere. **No uppercase, no tracked eyebrows.** Section labels are sentence-case titles.
- **Mono is for machine identifiers only:** hostnames, URLs, paths, relay names, IP addresses, rule text. It is set at 0.93em of the role it sits in (optical match), so it never adds a size to the scale. Mono is never a label, a heading, a number or decoration.
- **Numbers use the sans with tabular figures** (`font-variant-numeric: tabular-nums`, SwiftUI `.monospacedDigit()`), including table columns. Tabular SF digits align as well as mono and do not change the voice of the row.
- Weight carries hierarchy inside a size: 600 for the thing, 400 for its description. Never use colour for emphasis.

---

## 4. Colour

### Tokens (light / dark) and measured contrast

Contrast is WCAG 2.x relative luminance, against `--paper` unless stated; also checked on `--raised`.

| Token | Light | Ratio | Dark | Ratio | Role |
|---|---|---|---|---|---|
| `--paper` | `#f5f5ef` | — | `#0f1713` | — | Page ground |
| `--raised` | `#fbfbf7` | — | `#17221d` | — | Controls, the popover body |
| `--sunken` | `#ebebe3` | — | `#0a110e` | — | Segmented track, placeholder, skeleton |
| `--ink` | `#182721` | 14.2 | `#e6e8df` | 14.7 | Text |
| `--muted` | `#56645d` | 5.7 (5.2 on sunken) | `#9aa69f` | 7.2 (6.5 on raised) | Secondary text |
| `--faint` | `#7d8882` | 3.4 | `#76827b` | 4.6 | Graphics only (non-current bars, ticks). Never text. |
| `--line` | `#dcddd3` | 1.25 | `#26332d` | 1.4 | Decorative hairline between list rows; carries no meaning |
| `--edge` | `#7c8780` | 3.4 | `#64726b` | 3.6 | Boundary of an interactive control (≥ 3:1) |
| `--fill-primary` | `#19382e` forest | on-primary 12.3 | `#cfe3d6` | on-primary 13.6 | The single primary button; brand mark |
| `--focus` | `#2f6f58` | 5.4 | `#8fc9ac` | 9.7 | Focus ring |
| `--select` | ink at 7% | ink on it 12.8 | ink at 8% | — | Hovered or selected row |
| `--protected` | `#235843` | 7.5 | `#7fb89c` | 8.0 | State |
| `--reduced` | `#82521d` | 6.1 | `#d6a25f` | 8.0 | State |
| `--unprotected` | `#913f37` | 6.5 | `#e08a7f` | 7.0 | State |
| `--threat` | = unprotected | | = unprotected | | State |
| `--protected-tint` / `--reduced-tint` / `--threat-tint` | `#e3eee6` / `#f4ead9` / `#f5e6e2` | state text on tint 6.9 / 5.6 / 5.8 | `#16271f` / `#2b2216` / `#2e1b18` | 6.9 / 6.8 / 6.3 | Callout ground only |

All text pairs pass 4.5:1; all control boundaries and meaningful graphics pass 3:1. `--line` deliberately does not: a hairline between rows is decoration, never the only cue that something is interactive.

### States (the only hues)

| State | Means | Token | Where it shows |
|---|---|---|---|
| Protected | Every layer that should be on is on and current | `--protected` | Status dot and word; a layer that is up; a KPI on target |
| Reduced | Protection works but with a known gap (stale lists, companion in some profiles, a KPI to watch) | `--reduced` | Status dot and word; dashed Path wall; one callout with the fixing action |
| Unprotected | A layer is down or paused; traffic is passing unfiltered | `--unprotected` | Status dot and word; broken Path wall; KPI off target |
| Threat | A threat-listed destination is being shown or reached | `--threat` | Warning page state line; a threat row in a list; a threat hour in a chart |
| Neutral | Not measured, not applicable, loading, information | `--muted` / hollow dot | "Not filtered", "Checking…", information KPIs |

Rules:
- State colour appears on a **dot plus a word** (never colour alone) or on a data mark that has a text label nearby.
- A *stopped* threat is good news: its count is neutral ink. Threat colour is for something the user must look at now.
- Brand forest appears only as the primary-button fill and the brand mark. No forest hero blocks, no coloured headings, no green bars for "blocked".
- Charts: one series in ink (current period) and `--faint` (other periods). A state hue in a chart marks a state event (threat hour), labelled in text.

---

## 5. Elevation and lines

- Three grounds only: paper (page), raised (controls; the Mac popover), sunken (tracks, placeholders). No card surfaces for content; content sits on paper.
- Shadow: only on things that float above the page (Mac popover, toast). `--shadow-pop`.
- A line is allowed for: (a) hairline between rows of one list (`.list`), inset to the text edges; (b) the bottom of a tab bar or toolbar; (c) the boundary of a control (`--edge`); (d) one rule between the focal block and the drill-down on the dashboard and Mac Overview; (e) the 2px state rule above a decision page's status line. Nothing else.
- Radius: 6 for controls and callouts, 10 for surfaces (placeholder, popover 12 per macOS).

---

## 6. Components

All in `tokens.css`. Sizes are web px; macOS uses the same numbers in pt unless noted.

| Component | Anatomy | Sizes | States and rules |
|---|---|---|---|
| **Status header** `.status` | 8 dot · state word (600, state colour) · one fact (muted) | Body on the popup header (caption), title on dashboard, headline on Mac Overview | One per view, top-left. The fact names the cause in ≤ 8 words ("2 block lists are 3 days old"). Never a pill, never a coloured block. |
| **Metric** `.metric` | value above label | Value in display (focal), headline (wide secondary) or title (compact secondary); label body (focal) or caption | Label is a lower-case noun phrase that completes the number ("blocked today"). No pills, no inline unit sentences, no icons. Zero is shown as `0`, not hidden. |
| **Metric row** `.metric-row` | 2–4 metrics in equal columns | Gap 16; at ≤ 720 wraps to 2 columns | All values in a row share one role and one baseline. Never more than four. |
| **List row** `.row` | lead (optional) · main (line 1, line 2 caption) · trail | Min 44 tall (two-line), 40 (one-line, wide), 28 (Mac table) | Line 1 never wraps; it truncates by section 8. Rows bleed 8 into the gutter so the hover/selection fill (`--select`) clears the text. |
| **Trailing action** `.row .act` | secondary button in the trail | 28 tall | Hidden at rest (`display: none`, so the text gets the full width); shown on hover, keyboard focus or selection. **Never repeated down a list at rest.** |
| **Segmented control** `.seg` | sunken track, 2–4 equal segments, selected segment raised + 600 | 32 tall (popup, dashboard), 24 (Mac toolbar) | One choice that applies immediately. ≤ 4 segments, each label ≤ 10 characters at the narrowest width. Descriptions go in the AX description/tooltip, not under the control. |
| **Tabs** `.tabs` | text labels, 2 px ink underline on the current tab, count in muted tabular | 36 tall | Second-level navigation (popup, dashboard drill-down, scorecard lists). Labels must fit at the narrowest width; shorten the label, never scroll or clip. |
| **Buttons** `.btn` | Primary (forest fill), secondary (raised + edge), quiet (underlined text, no padding so it aligns to text edges) | 28 desktop (`--hit`), 40 `.lg` on decision pages, 44 on touch | Labels are verbs. ≤ 1 primary per view. Destructive or risky actions are secondary and confirm inline. |
| **Switch** `.switch` | 32 × 20 track, 16 knob | Sits at the right end of a `.setting` row, 44 tall | For on/off settings that apply at once. On = forest fill (not a state colour). |
| **Text field** `.field` | edge, raised ground | 32 tall, same as an adjacent button | Placeholder is a noun ("Domain", "Search"). |
| **Disclosure** `details.disclosure` / `details.kpi` | chevron + summary row | Summary ≥ 28 tall | For evidence and detail, never for primary controls. |
| **Empty state** `.empty` | title (16/600) · one muted sentence · optional secondary button | 32 top padding | Says what will appear and when; never "No data". Every second-level view has one. |
| **Loading** `.skeleton` / `.sk` | sunken bars at the real text widths | — | Layout does not move when data arrives. State word reads "Checking…" with a hollow dot. No spinners longer than 1 s. |
| **Error** `.inline-error` | one line in unprotected colour, next to the thing that failed | Body | Says what failed and what to do; keeps the last good data visible. |
| **Toast** `.toast` | ink ground, paper text, optional quiet Undo | Bottom-centre, 4 s | Only to confirm an action that changed something out of view ("Allowed for 15 min · Undo"). |
| **Callout** `.callout` | state-tint ground, 3 px state edge, one sentence, one button | 12/16 padding | Only where the status header has no room for the fixing action (the 360 px popup). One per view. |
| **Bar strip** `.bars` | equal bars on a baseline; `--faint` bars, the current period in ink, empty periods as a 1 px line | 24–120 tall; 2–4 gap | One series. Axis: 4–5 tabular labels, first and last always "start" and "Now". Head: what it counts on the left, one notable fact on the right ("Peak 15 at 10:00"). No legend for a single series. |
| **Timeline / Path** (Mac) | This Mac · four walls · Internet, each wall 8 wide | 136 tall walls | See section 12. |
| **7-day state strip** (scorecard) | seven 10 × 10 squares, state fill; hollow = not measured | 4 gap | Replaces per-KPI value trend bars that were each scaled to their own maximum. |
| **Tag** `.tag` | sunken pill, caption | 20 tall | A category noun in a dense list when grouping is impossible. Not for state (use dot + word), not for counts, never more than one per row. The redesign currently uses none: grouping replaced every tag. |

---

## 7. Formatting

- **Counts:** grouped thousands with the locale separator (`56,417`). Below 10,000 exact; from 10,000 in compact views use one decimal and a unit (`1.9M block rules`). Never `1.87M` next to `1,204` in the same row: one style per row.
- **Percentages:** as many decimals as the target needs plus one, trailing zeros dropped except to show the target precision (`99.55%` against ≥ 99%; `100%`, not `100.00%`). Never more than two decimals.
- **Durations:** `13 h`, `4 min`, `2 d` with a thin space-free unit; `just now` under 45 s.
- **Relative times** in lists: `2 min ago`, `2 h ago`, then `Nov 18` after 24 h. **Absolute times:** 24-hour `14:32`, with seconds only in the Mac Activity table. Dates: `Nov 18, 2026`; the year is dropped inside the current year in dense views.
- **Hostnames:** lower-case, punycode shown as-is (`xn--pypal-4ve.com`) with the Unicode form only in a warning sentence. Never strip `www.` (it is a different host). URLs show host in ink and path in muted.
- **Relay names, IPs:** mono, never broken across lines (`white-space: nowrap` on the token; the surrounding sentence may wrap).

---

## 8. Truncation

What may truncate: line 1 of a list row (hostname, URL, list name); a table cell; the popup header host. What must wrap instead: headlines, sentences, status facts, empty states, warning-page hosts and URLs (they wrap anywhere with `overflow-wrap: anywhere`; on the warning page the full address is the information), metric labels, button labels (shorten the label instead).

Rules:
1. **Hostnames truncate in the middle, by whole labels.** Keep the first label and the registrable domain (`example-enterprise.co.uk`), replace dropped labels with `…`, add labels back from the left while they fit: `eu-west-2.cdn.….example-enterprise.co.uk`. If only the registrable domain fits: `….example-enterprise.co.uk`. Only if the registrable domain alone does not fit, cut inside it, in the middle. Never cut inside a label otherwise. Reference implementation: `fitHost()` in [`mockups/mac-activity.html`](mockups/mac-activity.html).
2. **URLs keep the host whole and truncate the path in the middle by segment:** `publisher.example/…/gtm.js`; if host + last segment do not fit, `host/…`.
3. Free text (list names, reasons) truncates at the end with `…`.
4. Everything truncated has the full value in `title` (web) / `.help()` and the accessibility label (macOS).
5. Truncation is computed for the space the row has **in that state**: a selected row with its action showing re-truncates; a hidden action takes no space.
6. A clipped glyph (cut by `overflow: hidden` without an ellipsis) is an automatic fail. `capture.mjs` reports it.

---

## 9. Writing

- **Labels are nouns** ("blocked today", "Protection on this site", "Block lists"). **Buttons are verbs** ("Go back", "Resume protection", "Allow 15 min", "Update lists"). An ellipsis on a button means it asks for more before acting ("Continue anyway…", "Add…").
- **No explanatory captions.** If a graphic or control needs a sentence explaining how to read it, redesign it. Allowed sentences: the one fact that changes the decision ("Your browser did not contact this site."), an empty-state sentence, a consequence on a confirmation step.
- Sentence case everywhere. No ALL CAPS. No exclamation marks.
- Name the cause, not the mechanism: "2 block lists are 3 days old", not "Feed refresh job last succeeded at…".
- One term per idea: "blocked" (not refused/denied/stopped) for filtered requests; "threat" for malware/phishing; "Paused" for user-initiated off; "Off" for a layer that is down.
- Numbers lead: "38 requests blocked", not "Blocked requests: 38".

---

## 10. Motion

- Durations: 120 ms (`--dur-fast`) for hover/press, 200 ms (`--dur`) for reveal and layout. Easing `cubic-bezier(.2, 0, 0, 1)`.
- Allowed: disclosure chevrons rotate; a revealed confirmation fades and expands; numbers change with a numeric content transition (SwiftUI `.contentTransition(.numericText())`); a Path wall opening or closing animates its gap (spring, 0.4 s).
- Not allowed: anything that loops, pulses or animates on load; chart bars growing on first draw.
- `prefers-reduced-motion: reduce` / Reduce Motion: every transition becomes an instant change (`tokens.css` zeroes durations).

---

## 11. Accessibility

- **Focus order** follows reading order: status, focal metric (read as one element, "5 requests blocked on this page"), secondary metrics, primary control, then tabs' panels. The primary button gets initial focus on decision pages (`autofocus` on Go back / Continue through the scanner).
- **Focus ring:** 2 px `--focus`, 2 px offset, on every interactive element; never removed.
- **Hit targets:** 28 × 28 minimum on desktop (`--hit`), 44 × 44 on touch (`pointer: coarse` raises `--hit`), list rows ≥ 44 tall in the popup.
- **Contrast:** section 4; checked for both schemes.
- **VoiceOver / labels:** status = "Protection: Reduced. Chrome companion is in 11 of 13 profiles." Metrics read value then label. State dots are `aria-hidden`; the word carries the state. The Path is one element with a label listing each wall and state, in traffic order. Bar strips have an `aria-label` summary ("Blocked per hour, last 24 hours, peak 15 at 10:00"). Truncated hostnames expose the full value. The 7-day strip reads its seven states.
- **Keyboard:** popup tabs are arrow-key navigable; list rows are focusable and reveal their action on focus; Esc closes a confirmation; ⌘F focuses search on the Mac.
- **Colour is never the only cue** (principle 2, every state has a word).

---

## 12. Information architecture, per surface

### Popup (360 × ≤ 520)
**Decision:** a main view that answers "what did Egress Guard do on this page" and holds the one control; three second-level tabs for everything else.
- Header (48): brand mark · site host (mono, truncates by section 8) · status dot and word.
- Tabs (36): **This page · Blocked n · Rules n · Settings**.
- This page: focal metric (requests blocked on this page, display) → metric row of exactly three facts (links cleaned, cookies removed, elements hidden) → "Protection on this site" with **Pause** as a quiet trailing button and the four-level segmented control. Natural height ≈ 410, so it fits 520 with room for the reduced callout.
- Paused (Pause sets the site to Relaxed with no hiding or cleaning for 15 minutes): the header reads **Paused** in the reduced state; one callout "Paused on this site until HH:MM" with **Resume** as the filled (safe) button, and one muted line under it, "Malware and phishing blocking stays on."; the level control shows the level that will be restored, disabled.
- Blocked: grouped by reason (group title + count), one row per request: URL (host ink, path muted) and type. **"Allow 15 min" lives in the row's trailing action, shown only on hover, focus or selection**, so it is never repeated at rest.
- Rules: rules for this site (Add… in the heading), temporary exceptions with time left, and page tools as action rows (Block an element…, Show hidden ad slots, Restore everything hidden here).
- Settings: default level for other sites, the mail-scanner switch, and list provenance (list name and update date).
- Empty states: zero blocked shows `0` (not a special screen); a browser page shows "Chrome pages can't be filtered"; Blocked and Rules each have an empty state.
*Why:* the current popup stacks eight equal sections to ~2,000 px. One number, three facts and one control is what a user opens the popup for; everything else is occasional and reached by name.

### Decision pages (threat warning, scanner interstitial, unwrap failure)
Stopping someone before a threat-listed site is the most consequential moment in the product, so these pages carry the most weight of any view.
- **Headline is the answer, at display size** (48/48, 600, balanced wrapping). At ≤ 480 px a sentence at display size is too large for the 358 px column, so it steps down to headline (24/30); this is the only place display carries words.
- **The hostname is the second-largest thing:** mono at the title size (16/22, 600), not 0.93em, breaking only between labels (each label with its dot is one box; a label wider than the column wraps inside it rather than clip). The full URL follows in caption, muted, wrapping anywhere.
- **Vertical placement:** on desktop the column's top edge sits at one third of the viewport height (`max(48px, 33.333vh − bar)`, the named viewport-derived spacing exception), so the decision sits at the optical centre rather than under the brand mark. At ≤ 480 px the column is top-aligned on the standard margin (32 below the bar).
- **One state element:** state is carried by the status line in the state colour (dot + word) and one structural element only, a 2px rule in the same colour above the status line, spanning the column. Neutral pages (scanner link, unwrap failure) use the muted state for both. No tinted panels, no icons, no coloured headings; the Continue confirmation is plain text and a secondary button.

### Threat warning page
**Decision:** one decision per page. State line (threat) → headline → host (title, mono) and full URL → list and update date → one fact sentence → **Go back** (primary, focused) and **Continue anyway…** (quiet). Continue reveals the consequence sentence and a secondary "Open <host> once" (plain, untinted; Escape closes it).
*Why:* the safe action must be the obvious one; the risky one takes two deliberate clicks and names the host it opens.

### Scanner-link interstitial
**Decision:** the question is the headline ("Open this link through Microsoft Defender?"). Destination host and URL, then **Continue through Defender** (primary) and **Open directly** (secondary). The fine print about popup settings is removed (it is in Settings). An IDN destination turns the status line and its rule to the reduced state ("Mail scanner link with look-alike letters") and adds one sentence naming the look-alike; no callout. The unreadable-tracker variant is the same page with **Go back** primary and **Copy link** quiet.

### Click-to-load placeholder
**Decision:** fills the embed's own box on a sunken ground; "Held by Egress Guard" (caption) → provider and kind as title ("YouTube video") → **Load video** (primary) and **Load signed in** (quiet). A refused click adds one line in the unprotected colour and nothing else moves. No dashed border, no paragraph.

### Dashboard
**Decision:** above the fold answers "am I protected, and what did it stop today": status header (with its fixing action when reduced) → focal metric (blocked today, with share and change) beside a one-series 24-hour bar strip → four reason metrics (threats stopped, ads and trackers, cloaked trackers, by your rules). Everything else is drill-down tabs: **Activity · Top blocked · Threats**. The health strip, the separate breakdown blocks and the explanatory footer are removed; the reduced state no longer needs a separate callout because the status row carries "Update lists".

### Scorecard
**Decision:** the focal element is the count off target with their names ("4 of 11 off target: Threat stops, Bypass exposure, IP exposure, Resource cost"), then three groups (Security 5, Anonymity 5, Efficiency 1) with an "n of m on target" count. **A KPI row is one line:** state (dot + word) · name · value (title, right-aligned, tabular) · target · 7-day state strip. Evidence (hosts, paths, method notes) moves into the row's disclosure; one example is shown open. Today's lists become tabs (**Got through · Threats · Feeds**). The two forest hero cards are removed.
*Why:* eleven rows that share one value edge and one state column can be scanned in ten seconds; paragraphs under each KPI could not.

### Mac popover (340 pt)
**Decision:** status (dot, word, one cause) → three numbers (Blocked today, Threats stopped, Trackers saw you) → four layer rows in traffic order, each **two lines**: name · state word, then the detail on its own line (so "Chicago, USA · lockdown on · us-chi-wg-307" and "Missing in Work 2 and Guest" never clip) → menu actions (Open ⌘O, Refresh ⌘R | Restore internet…, Quit ⌘Q). Restore internet confirms inline with **Cancel** as the primary. Loading uses skeletons at real widths. The mini Perimeter is removed.

### Mac main window, Overview
**Decision:** one focal element, the **Path**: This Mac on the left edge, the internet on the right edge, and the four walls between them in the order traffic crosses them (Chrome companion, Filtering proxy, DNS filter, Mullvad tunnel). A wall that is up is a solid bar; a reduced wall is dashed; a wall that is down has a hole in the middle. Each wall is labelled with its name, state word and one detail. Below a single rule: three numbers in headline, then today's blocked-per-hour strip with any threat hour marked and named in the strip's head.

### The Perimeter: decision
**Replace it with the Path; keep the rings only as the identity mark (menu-bar glyph and app icon).**
The Perimeter fails the two-second test for three measurable reasons: (1) concentric rings carry no labels, so ring-to-layer mapping needs the caption or a legend (the shipped Overview has both); (2) at 92 pt in the popover the four rings sit 4 pt apart and an amber ring is indistinguishable from a green one; (3) the 24-hour ticks on a circle cannot be compared by length the way bars on a baseline can, and they need the second half of the caption. The Path keeps the idea that made the Perimeter worth having (walls in traffic order; a wall that is down is literally a hole) and drops the encoding the reader must learn. The ring motif survives where it is identity, not data: three arcs in the menu bar (with the existing opened-arc states) and the app icon.

### Mac Activity (list view)
Toolbar: title with count, All/Blocked/Allowed segmented control, search. Table: Time (tabular) · Decision (Blocked 600 / Allowed muted) · Host (mono, `fitHost`) · Reason (muted, ends truncate). Threat rows use the threat colour on decision and reason only. Selection uses `--select`.

---

## 13. Do / don't

[`do-dont.html`](do-dont.html) shows each crop of the current UI with numbered annotations next to the redesigned equivalent. Summary:

| Don't (current) | Do (this system) |
|---|---|
| Forest hero block with ragged category chips (popup) and two forest KPI cards (scorecard) | Focal number on paper; categories become groups on the Blocked tab |
| "Allow 15 min" repeated on every row, the last one half-visible at the scroll edge | Trailing action only on the hovered or selected row |
| "In 11 of 1…e profiles", "Example City…· lockdown on" (popover) | Two-line layer rows; detail on its own line; nothing clipped |
| A caption under the ring explaining rings and ticks | The Path, labelled in place; a threat hour named in the strip head |
| Tracked uppercase mono eyebrows on every block | Sentence-case titles; mono only for hostnames |
| Three big-number treatments on one screen (alone, with a pill, with an inline label) | One metric component: value above label |
| A four-way segmented control, a dropdown and a disclosure in one block, each with a paragraph | One segmented control; defaults moved to Settings; descriptions in tooltips |

---

## 14. Self-review log

The captures were audited by `capture.mjs` (clipped text, off-scale spacing, type sizes in use, primary buttons per view) and by eye against these rules, as a hostile reviewer. Each pass was fixed and re-captured.

**Pass 1** (first draft → second):
1. Clipped: popup long host `accounts.….example-enterpri` — rule 8.1 applied (`….example-enterprise.co.uk`), header host set at mono 13.
2. Clipped: popup Blocked rows (`/g/collec`, `securepubads.g.doubleclick`) because the hidden action still reserved width — actions now `display: none` at rest; paths truncate by segment.
3. Clipped: Mac Activity `…example-enterprise.co.` — `fitHost()` added and specified.
4. Clipped: scorecard tabs at 390 ("Feed…") — labels shortened to Got through / Threats / Feeds.
5. Broken token: Mac Overview relay split as `us-` / `chi-wg-307` — relay is `nowrap` on its own line.
6. Caption explaining the design: "Red: an hour a threat was stopped" — replaced by a named event in the strip head.
7. Wrong focal emphasis: dashboard chart drew allowed traffic large and blocked as a sliver — one series (blocked), current hour in ink.
8. Meaningless graphic: scorecard trend bars each scaled to their own max (all full height) — replaced by a 7-day state strip.
9. Alignment: quiet buttons had 8 px padding and sat off the text edge; warning-page brand sat 440 px left of the column — quiet buttons have no side padding; brand bar shares the column edge.
10. Ragged: popup page-tool buttons wrapped to two lines — action rows. Dashboard status fact wrapped beside the word at 390 — fact takes its own line, indented to the word.
11. Unexplained numbers: list provenance counts (2, 2, 1, 32) — replaced by update dates.
12. Selection fill touched the text — rows bleed 8 into the gutter; hairlines stay on the text edges; `--select` token added.

**Pass 2** (second → final):
1. Duplicated state text: dashboard reduced showed the cause twice (status fact and callout) — callout removed; "Update lists" sits in the status row.
2. Overlap: threat label drawn over neighbouring bars in the Mac strip — moved to the strip head in the threat colour.
3. Duplicated cause in the popover (header and Chrome row both said "11 of 13") — row says "Partial" and names the missing profiles.
4. Off-scale spacing found by the audit: popover rows 6/10 px → 4/12 (menu text now on the 16 edge); Overview dot 10 + 12 gap → 12 + 12 so the fact indent is 24.
5. Unlabelled 7-day squares at 390 — the "Last 7 days" column head is kept on phones.
6. Popup Rules exceeded the 520 budget — "Add…" moved into the section heading; page tools gained a chevron so they read as actions.
Final audit: 0 clipped elements in 40 frames/pages, 0 views with more than one primary button, no horizontal scroll at 390; remaining off-scale values are the named grid-derived exceptions.

---

## 15. Reconciliation with the Mac app's `DESIGN.md`

One token set. The app's `Theme.swift` palette maps one to one:

| App (`Palette`) | This system | Change |
|---|---|---|
| paper `#F5F5EF` / `#0F1713` | `--paper` | none |
| surface `#FBFBF7` / `#16211C` | `--raised` `#fbfbf7` / `#17221d` | dark +1 step so muted text keeps 6.5:1 on it |
| ink `#182721` / `#E6E8DF` | `--ink` | none |
| muted `#5B6A63` / `#97A39D` | `--muted` `#56645d` / `#9aa69f` | light darkened: 4.75 → 5.2 on sunken |
| line `#DCDDD3` / `#26332D` | `--line` | none |
| faint `#E9EAE1` / `#1E2B25` | `--sunken` `#ebebe3` / `#0a110e` | renamed; dark sunken goes below paper so tracks read as recessed |
| forest `#19382E` | `--fill-primary` | light only; dark uses `#cfe3d6` so the primary button stays the brightest control |
| accent `#235843` / `#7FB89C` | `--protected` | renamed: it is a state, not an accent |
| warn `#82521D` / `#D6A25F` | `--reduced` | renamed |
| bad `#913F37` / `#E08A7F` | `--unprotected`, `--threat` | renamed |
| — | `--faint`, `--edge`, `--focus`, `--select`, tints | added |

Type changes for the app: Display 72 mono → 44 SF Pro semibold with monospaced digits; the Eyebrow (10.5 mono, tracked, uppercase) and the `StateChip` capsule are retired in favour of sentence-case titles and dot + word. Rows, numbers and the Path follow section 6 and 12.

---

## Open questions for the owner

1. **Popup tabs on top or a details view?** Tabs on top are specified (fast, always visible). A bottom bar (uBlock-style) saves no height and was rejected; a "Details ›" drill-in would hide the counts.
2. **Pause vs Relaxed.** The spec keeps four levels plus a quiet Pause. Folding Pause into the control as "Off" would make it one choice of five, too wide at 360.
3. **Path direction.** This Mac on the left, Internet on the right (traffic flows outward). If you read the walls as "keeping the internet out", the reverse may feel better.
4. **Primary fill in dark mode** is pale (`#cfe3d6`), not forest, so it stays the brightest control. Confirm you prefer this over a dark forest button.
5. **Scorecard focal number** counts off-target KPIs (an alarm count). The alternative is "5 of 11 on target" (a progress count).
