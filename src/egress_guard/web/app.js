'use strict';

const $ = (id) => document.getElementById(id);
const SVG = 'http://www.w3.org/2000/svg';
const hourFormat = new Intl.DateTimeFormat(undefined, {hour: '2-digit', minute: '2-digit', hourCycle: 'h23'});
const timeFormat = new Intl.DateTimeFormat(undefined, {hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'});
const dayFormat = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric'});
const weekdayFormat = new Intl.DateTimeFormat(undefined, {weekday: 'short'});
const utcDayFormat = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric', timeZone: 'UTC'});
const utcWeekdayFormat = new Intl.DateTimeFormat(undefined, {weekday: 'short', timeZone: 'UTC'});
const dateFormat = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'});
const numberFormat = new Intl.NumberFormat();
const percentFormat = new Intl.NumberFormat(undefined, {style: 'percent', maximumFractionDigits: 1});
const PAGE = 15;

const stateLabels = {
  active: ['Active', 'good'], admin_required: ['Needs admin', 'warn'], allowed: ['Allowed', 'good'], blocked: ['Blocked', 'bad'],
  degraded: ['Needs attention', 'warn'], disabled: ['Off', ''], down: ['Unavailable', 'bad'],
  enabled: ['Enabled', 'good'], failed: ['Failed', 'bad'], fresh: ['Current', 'good'],
  healthy: ['Healthy', 'good'], installed: ['Installed', 'good'], maintenance_blocked: ['Deferred', 'warn'], observed: ['Observed', ''],
  offline: ['Offline', 'bad'], ok: ['OK', 'good'], paused: ['Paused', 'warn'],
  pending: ['Pending', 'warn'], ready: ['Ready', 'good'], restart_required: ['Needs restart', 'warn'], stale: ['Stale', 'warn'],
  unavailable: ['Unavailable', ''], unknown: ['Not checked', ''],
};
// Ledger block sources in plain language. Unknown values are shown as recorded.
const reasons = {
  'tracker-feed': 'Ad or tracker list', tracker: 'Ad or tracker list', ads: 'Ad or tracker list',
  'cname-feed': 'Cloaked tracker (CNAME)', 'cname-cloak': 'Cloaked tracker (CNAME)',
  'threat-intel': 'Threat intelligence', malware: 'Malware', phishing: 'Phishing',
  'local-block': 'Your block rule', 'local-allow': 'Your allow rule', 'temporary-exception': 'Temporarily allowed',
  'tracker-paused': 'Ad filtering paused', 'dashboard-exception': 'Exempt dashboard host', 'no-match': 'No rule matched',
  'plaintext-credentials': 'Password sent unencrypted', 'not-ready': 'Filters not ready', 'non-tls-tunnel': 'Non-TLS tunnel refused',
  'invalid-host': 'Malformed hostname', 'invalid-request': 'Malformed request', doh: 'Encrypted DNS bypass',
};
const sourceCategory = {
  'threat-intel': 'threats', malware: 'threats', phishing: 'threats',
  'tracker-feed': 'ads', tracker: 'ads', ads: 'ads', 'cname-feed': 'cname', 'cname-cloak': 'cname', 'local-block': 'manual',
};
const categoryLabels = {threats: 'Malware and phishing', ads: 'Ads and trackers', cname: 'Cloaked trackers (CNAME)', manual: 'Your block rules', other: 'Other protections'};

const records = new Map();
let status = null;
let insights = null;
let events = null;
let activityMeta = {history: 'full', dropped: 0};
let range = 'day';
let decisionFilter = 'all';
let shown = PAGE;
let refreshPromise = null;
let lookupController = null;
let lookupResult = null;
let actionRequest = null;
let submitting = false;
let authExpired = false;
let detailTouched = false;
let bearer = '';
try { bearer = sessionStorage.getItem('egress-guard.session') || ''; } catch {}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function svg(tag, attributes = {}) {
  const node = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, value);
  return node;
}

function date(value) {
  if (!value) return null;
  const normalized = typeof value === 'number' && value < 1e12 ? value * 1000 : value;
  const parsed = new Date(normalized);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function formattedDate(value, formatter = dateFormat) {
  const parsed = date(value);
  return parsed ? formatter.format(parsed) : '';
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function plural(value, one, many) {
  return numberFormat.format(value) + ' ' + (value === 1 ? one : many);
}

function ago(value) {
  const parsed = date(value);
  if (!parsed) return '';
  const seconds = Math.max(0, (Date.now() - parsed.getTime()) / 1000);
  if (seconds < 45) return 'just now';
  if (seconds < 3600) return Math.round(seconds / 60) + ' min ago';
  if (seconds < 86400 && parsed.toDateString() === new Date().toDateString()) return Math.round(seconds / 3600) + ' h ago';
  const yesterday = new Date(Date.now() - 86400000);
  if (parsed.toDateString() === yesterday.toDateString()) return 'yesterday ' + hourFormat.format(parsed);
  return dayFormat.format(parsed);
}

function timeNode(value, dayOnly) {
  const parsed = date(value);
  if (!parsed) return element('span', '—');
  const node = element('time', dayOnly ? (parsed.toISOString().slice(0, 10) === new Date().toISOString().slice(0, 10) ? 'today' : utcDayFormat.format(parsed)) : ago(parsed));
  node.dateTime = parsed.toISOString();
  node.title = dayOnly ? utcDayFormat.format(parsed) + ' (UTC day)' : dateFormat.format(parsed) + ' · ' + timeFormat.format(parsed);
  return node;
}

function reasonText(source) {
  return Object.hasOwn(reasons, source) ? reasons[source] : (typeof source === 'string' && source ? source : '—');
}

function categoryOf(source) {
  return Object.hasOwn(sourceCategory, source) ? sourceCategory[source] : 'other';
}

function badge(state) {
  const [label, style] = Object.hasOwn(stateLabels, state) ? stateLabels[state] : stateLabels.unknown;
  return element('span', label, style ? 'state ' + style : 'state');
}

function notice(id, message, isError = false) {
  const node = $(id);
  node.textContent = message;
  node.hidden = !message;
  node.classList.toggle('error', isError);
}

function changed(key, value) {
  const signature = JSON.stringify(value ?? null);
  if (records.get(key) === signature) return false;
  records.set(key, signature);
  return true;
}

function expiredSession() {
  bearer = '';
  try { sessionStorage.removeItem('egress-guard.session'); } catch {}
  authExpired = true;
  status = null;
  insights = null;
  events = null;
  activityMeta = {history: 'full', dropped: 0};
  records.clear();
  clearLookup();
  for (const id of ['activity-rows', 'proxies', 'canaries', 'filters', 'maintenance', 'security', 'temporary-allows', 'categories', 'top-domains', 'chart', 'threat-list']) {
    $(id).replaceChildren();
  }
  $('dashboard').hidden = true;
  $('refresh').hidden = true;
  $('confirm').close();
  $('hostname').value = '';
  notice('notification', '');
  notice('connection', 'Open the Egress Guard launcher on this Mac to start a new dashboard session.');
  document.body.dataset.ready = '1';
}

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      credentials: 'omit',
      cache: 'no-store',
      signal: options.signal || AbortSignal.timeout(12000),
      ...options,
      headers: {'Accept': 'application/json', 'X-Mac-Guard': '1', ...(bearer ? {'Authorization': 'Bearer ' + bearer} : {}), ...options.headers},
    });
  } catch (error) {
    if (error.name === 'AbortError') throw error;
    throw new Error('The local protection service could not be reached. Try again.');
  }
  if (response.status === 401) {
    expiredSession();
    throw new Error('Open the Egress Guard launcher to sign in again.');
  }
  const isJSON = response.headers.get('content-type')?.includes('application/json');
  const body = isJSON ? await response.json().catch(() => null) : null;
  if (!response.ok || !body) {
    const supplied = typeof body?.message === 'string' ? body.message : body?.error;
    throw new Error(typeof supplied === 'string' && supplied.length < 500 ? supplied : 'The local service could not complete that request.');
  }
  return body;
}

function durationOptions(values) {
  return Array.isArray(values) ? values.filter((value) => Number.isInteger(value) && value > 0 && value <= 60) : [];
}

function writable() {
  return Boolean(status && typeof status.csrf_token === 'string' && status.csrf_token);
}

function controls() {
  return writable() ? status.controls || {} : {};
}

/* ---------- Health line ---------- */

function proxyPort() {
  const detail = status?.proxies?.[0]?.detail;
  const match = typeof detail === 'string' && detail.match(/127\.0\.0\.1:(\d{2,5})/);
  return match ? match[1] : null;
}

function bytes(value) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index += 1; }
  return (value >= 10 || index === 0 ? Math.round(value) : value.toFixed(1)) + ' ' + units[index];
}

function duration(seconds) {
  if (seconds < 3600) return Math.max(1, Math.round(seconds / 60)) + ' min';
  if (seconds < 172800) return Math.round(seconds / 3600) + ' h';
  return Math.round(seconds / 86400) + ' days';
}

function renderHealth() {
  const protection = status?.protection || {};
  const state = ['active', 'paused', 'degraded'].includes(protection.state) ? protection.state : 'unknown';
  const filters = Array.isArray(status?.filters) ? status.filters : [];
  const proxies = Array.isArray(status?.proxies) ? status.proxies : [];
  const proxyUp = proxies[0]?.state === 'active';
  const policy = proxies[1];
  const stale = filters.filter((item) => item.state !== 'active');
  const facts = [];
  const add = (text, tone) => facts.push([text, tone]);
  let headline;
  let tone = state === 'active' ? 'active' : state === 'paused' ? 'paused' : 'degraded';

  if (!status) {
    headline = 'Status unavailable';
    tone = 'degraded';
    add('The protection service did not answer. Activity below may be out of date.', 'bad');
  } else if (state === 'active' || state === 'paused') {
    headline = state === 'active' ? 'Protected' : 'Ad filtering paused';
    if (state === 'paused') {
      const until = formattedDate(protection.pause_expires_at, hourFormat);
      add(until ? 'resumes at ' + until : 'resumes automatically');
      add('malware and phishing filtering stays on');
    } else {
      add(policy?.state === 'active' ? 'policy applied' : 'policy pending', policy?.state === 'active' ? '' : 'warn');
    }
    const updated = filters.map((item) => date(item.updated_at)).filter(Boolean).sort((a, b) => a - b)[0];
    if (stale.length) add(plural(stale.length, 'feed', 'feeds') + ' stale', 'warn');
    else if (updated) add('feeds updated ' + ago(updated));
    const footprint = status.footprint;
    if (footprint && typeof footprint === 'object') {
      const parts = [];
      if (Number.isFinite(footprint.rss_bytes)) parts.push(bytes(footprint.rss_bytes) + ' memory');
      if (Number.isFinite(footprint.uptime_seconds)) parts.push('up ' + duration(footprint.uptime_seconds));
      if (parts.length) add('proxy ' + parts.join(', '));
    }
    if (stale.length && tone === 'active') tone = 'attention';
  } else {
    const feedsReady = filters.length && !filters.some((item) => item.detail === 'missing');
    headline = !feedsReady || !proxyUp ? 'Not protecting yet' : 'Needs attention';
    if (!feedsReady) add('filter lists not downloaded', 'bad');
    if (!proxyUp) add('proxy not running', 'bad');
    if (feedsReady && proxyUp) add(policy?.detail || protection.message || 'The proxy has not applied the saved rules.', 'bad');
  }

  $('health').dataset.state = tone;
  $('health-state').textContent = headline;
  $('health-facts').replaceChildren(...facts.flatMap(([text, style], index) => {
    const span = element('span', text, style || null);
    return index ? [document.createTextNode(' · '), span] : [span];
  }));

  const c = controls();
  $('pause').hidden = state !== 'active' || !durationOptions(c.pause_minutes).length;
  $('resume').hidden = c.resume !== true;
  $('refresh-filters').hidden = c.refresh_filters !== true;
  $('pause-canaries').hidden = c.pause_canaries !== true;
  $('resume-canaries').hidden = c.resume_canaries !== true;

  // Calm when fine; open with guidance when protection is not running.
  if (!detailTouched) setDetail(tone === 'degraded');
  renderSetup(state, filters, proxyUp);
  for (const id of ['proxies', 'canaries', 'filters', 'maintenance', 'security']) renderChecks(id, status?.[id]);
  $('security-section').hidden = !Array.isArray(status?.security) || !status.security.length;
}

function setDetail(open) {
  $('health-detail').hidden = !open;
  $('health-toggle').setAttribute('aria-expanded', String(open));
}

function renderSetup(state, filters, proxyUp) {
  const steps = [];
  if (status && state === 'degraded') {
    const feedsReady = filters.length && !filters.some((item) => item.detail === 'missing');
    if (!feedsReady) steps.push(['Download the filter lists: ', 'egress-guard refresh']);
    if (!proxyUp) steps.push(['Start the proxy: ', 'egress-guard start']);
    const port = proxyPort();
    steps.push(['Point an app or browser at the HTTP proxy ', '127.0.0.1:' + (port || '…'), ' for both HTTP and HTTPS.']);
  }
  if (!changed('setup', steps)) return;
  $('setup').hidden = !steps.length;
  $('setup').replaceChildren(...steps.map(([lead, code, tail]) => {
    const item = element('li');
    const text = element('span', lead);
    text.append(element('code', code));
    if (tail) text.append(tail);
    item.append(text);
    return item;
  }));
}

function renderChecks(id, rows) {
  if (!changed(id, rows)) return;
  if (!Array.isArray(rows) || !rows.length) {
    $(id).replaceChildren(element('li', 'No status reported.', 'item-detail'));
    return;
  }
  $(id).replaceChildren(...rows.map((item) => {
    const row = element('li');
    const details = element('div');
    const entries = Number.isSafeInteger(item.entries) && item.entries > 0 ? numberFormat.format(item.entries) + ' domains' : '';
    const checked = formattedDate(item.checked_at);
    const published = formattedDate(item.published_at);
    const updated = item.updated_at ? 'downloaded ' + ago(item.updated_at) : '';
    details.append(element('p', item.name || 'Check', 'item-name'));
    const detail = item.detail === 'current' ? '' : item.detail;
    if (detail) details.append(element('p', detail, 'item-detail'));
    const metadata = [entries, published && 'published ' + published, updated, checked && 'checked ' + checked].filter(Boolean);
    if (metadata.length) details.append(element('p', metadata.join(' · '), 'item-meta'));
    row.append(details, badge(item.state));
    return row;
  }));
}

/* ---------- Outcome ---------- */

function historyMode() {
  const mode = insights?.history;
  return ['full', 'aggregate', 'none'].includes(mode) ? mode : null;
}

function hasHistory() {
  return Boolean(insights && count(insights.coverage?.rows) > 0);
}

function renderOutcome() {
  // generated_at moves on every poll; leaving it out means an unchanged ledger does not redraw anything.
  const {generated_at: _generatedAt, ...stable} = insights || {};
  if (!changed('outcome', [stable, range])) return;
  const mode = historyMode();
  const today = insights?.today;
  const number = $('hero-number');
  const note = $('history-note');
  note.replaceChildren();
  note.hidden = true;
  number.classList.remove('word');
  $('hero-share').textContent = '';
  $('hero-change').replaceChildren();
  $('outcome-label').textContent = mode === 'aggregate' ? 'Blocked today (UTC)' : 'Blocked today';

  if (!insights || !mode) {
    number.textContent = '—';
    number.classList.add('word');
    $('hero-share').textContent = insights?.message || 'Local history could not be read.';
  } else if (mode === 'none') {
    number.textContent = 'History is off';
    number.classList.add('word');
    $('hero-share').textContent = 'Filtering still runs. Nothing is written to disk, so there is nothing to count.';
    note.hidden = false;
    const how = element('p', 'To see what Egress Guard blocks, set ');
    how.append(element('code', 'history = "aggregate"'), ' (daily counts) or ', element('code', 'history = "full"'), ' under ', element('code', '[logging]'), ' in config.toml.');
    note.append(how);
  } else if (!hasHistory()) {
    number.textContent = 'Nothing yet';
    number.classList.add('word');
    $('hero-share').textContent = 'Counts start with the first connection through the proxy.';
    note.hidden = false;
    note.append(element('p', status?.protection?.state === 'active'
      ? 'Protection is running. Open a page in an app that uses the proxy and blocked requests appear here.'
      : 'Finish setup above, then use an app configured for the proxy.'));
  } else {
    const blocked = count(today?.blocked);
    const total = blocked + count(today?.allowed);
    number.textContent = numberFormat.format(blocked);
    $('hero-share').textContent = total
      ? percentFormat.format(blocked / total) + ' of ' + plural(total, 'connection', 'connections')
      : 'No connections yet today';
    renderChange(mode, blocked);
  }
  renderThreats(mode);
  renderTimeline(mode);
  renderBreakdown(mode);
}

function renderChange(mode, blocked) {
  const line = $('hero-change');
  // Full history compares with the same elapsed time yesterday; aggregate only has whole days.
  const basis = mode === 'full' ? insights.same_time_yesterday : insights.yesterday;
  if (!basis || basis.complete === false) {
    line.textContent = 'Not enough history to compare with yesterday.';
    return;
  }
  const previous = count(basis.blocked);
  if (mode === 'aggregate') {
    line.textContent = 'Yesterday: ' + numberFormat.format(previous) + ' blocked in the whole day.';
    return;
  }
  if (!previous) {
    line.textContent = blocked ? 'None blocked by this time yesterday.' : 'Same as this time yesterday.';
    return;
  }
  const delta = (blocked - previous) / previous;
  if (Math.abs(delta) < 0.005) {
    line.textContent = 'Same as this time yesterday.';
    return;
  }
  const strong = element('span', (delta > 0 ? '↑ ' : '↓ ') + percentFormat.format(Math.abs(delta)), delta > 0 ? 'up' : 'down');
  line.append(strong, ' ' + (delta > 0 ? 'more' : 'fewer') + ' than this time yesterday (' + numberFormat.format(previous) + ')');
}

function renderThreats(mode) {
  const threats = insights?.threats;
  const week = count(threats?.week);
  const today = count(threats?.today);
  const show = (mode === 'full' || mode === 'aggregate') && hasHistory();
  $('threats').hidden = !show || !week;
  $('threats-clear').hidden = !show || Boolean(week);
  if (!show) return;
  if (!week) {
    $('threats-clear').textContent = mode === 'aggregate' ? 'No malware or phishing blocked in the last 7 days.' : 'No malware or phishing seen in the last 7 days.';
    return;
  }
  $('threats-title').textContent = today
    ? plural(today, 'threat', 'threats') + ' stopped today' + (week > today ? ' · ' + numberFormat.format(week) + ' this week' : '')
    : plural(week, 'threat', 'threats') + ' stopped this week';
  const recent = Array.isArray(threats.recent) ? threats.recent.slice(0, 3) : [];
  $('threat-list').replaceChildren(...recent.map((item) => {
    const row = element('li');
    row.append(element('span', item.host, 'host'), element('span', reasonText(item.source)), timeNode(item.at));
    return row;
  }));
}

/* ---------- Timeline ---------- */

function series(mode) {
  if (mode === 'full' && range === 'day') return (insights.hourly || []).map((item) => ({...item, kind: 'hour'}));
  return (insights.daily || []).map((item) => ({...item, kind: mode === 'aggregate' ? 'utc-day' : 'day'}));
}

function niceMax(value) {
  if (value <= 4) return 4;
  const power = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 2.5, 5, 10]) if (step * power >= value) return step * power;
  return 10 * power;
}

function periodLabel(item, short) {
  const start = date(item.start);
  if (!start) return '';
  if (item.kind === 'hour') {
    if (short) return hourFormat.format(start);
    return hourFormat.format(start) + '–' + hourFormat.format(new Date(start.getTime() + 3600000));
  }
  const weekday = item.kind === 'utc-day' ? utcWeekdayFormat : weekdayFormat;
  const day = item.kind === 'utc-day' ? utcDayFormat : dayFormat;
  return short ? weekday.format(start) : weekday.format(start) + ' ' + day.format(start) + (item.kind === 'utc-day' ? ' (UTC)' : '');
}

function isPartial(item) {
  return item?.complete === false;
}

function readout(item, isLast) {
  const node = $('chart-readout');
  const next = document.createDocumentFragment();
  // Only touch the live region when the words change, so a poll does not announce it again.
  const show = () => { if (node.textContent !== next.textContent) node.replaceChildren(next); };
  if (!item) {
    const values = series(historyMode());
    const blocked = values.reduce((sum, value) => sum + count(value.blocked), 0);
    const total = values.reduce((sum, value) => sum + count(value.blocked) + count(value.allowed), 0);
    next.append(element('strong', numberFormat.format(blocked)), ' blocked of ' + numberFormat.format(total) + (range === 'day' && historyMode() === 'full' ? ' in the last 24 hours' : ' in the last 7 days') + (values.some(isPartial) ? ' (some periods are only partly recorded)' : ''));
    show();
    return;
  }
  const blocked = count(item.blocked);
  const total = blocked + count(item.allowed);
  if (isPartial(item) && !total) {
    next.append(periodLabel(item, false) + ' · no data recorded for this period');
  } else {
    next.append(periodLabel(item, false) + (isLast ? ' (so far)' : '') + ' · ', element('strong', numberFormat.format(blocked)), ' blocked of ' + numberFormat.format(total) + (isPartial(item) ? ' (partial: history does not cover the whole period)' : ''));
  }
  show();
}

function describe(item) {
  const blocked = count(item.blocked);
  const allowed = count(item.allowed);
  if (isPartial(item) && !blocked && !allowed) return periodLabel(item, false) + ': no data recorded';
  return periodLabel(item, false) + ': ' + numberFormat.format(blocked) + ' blocked, ' + numberFormat.format(allowed) + ' allowed' + (isPartial(item) ? ' (partial)' : '');
}

let chartPending = false;

function renderTimeline(mode) {
  const figure = $('timeline');
  const chart = $('chart');
  const show = (mode === 'full' || mode === 'aggregate');
  figure.hidden = !show;
  if (!show) return;
  // Redrawing would drop keyboard focus from the bar being read; apply it when focus leaves.
  chartPending = chart.contains(document.activeElement);
  if (chartPending) return;
  $('range-day').disabled = mode !== 'full';
  $('range-day').title = mode === 'full' ? '' : 'Hourly totals need full history';
  if (mode !== 'full') range = 'week';
  $('range-day').setAttribute('aria-pressed', String(range === 'day'));
  $('range-week').setAttribute('aria-pressed', String(range === 'week'));

  const values = series(mode);
  chart.classList.toggle('blank', !hasHistory());
  const width = Math.max(280, chart.clientWidth || 600);
  const height = chart.clientHeight || 240;
  const top = 8, bottom = 24, left = 0, right = 36;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const maximum = niceMax(Math.max(0, ...values.map((item) => count(item.blocked) + count(item.allowed))));
  const slot = plotWidth / Math.max(1, values.length);
  const gap = Math.min(range === 'day' ? 4 : 14, slot * 0.28);
  const root = svg('svg', {viewBox: `0 0 ${width} ${height}`, role: 'group', 'aria-label': 'Blocked and allowed connections per ' + (range === 'day' ? 'hour' : 'day') + '. Use the left and right arrow keys to read each one.'});
  const y = (value) => top + plotHeight - (value / maximum) * plotHeight;

  const blank = !hasHistory();
  for (const fraction of blank ? [] : [0.5, 1]) {
    root.append(svg('line', {x1: left, x2: left + plotWidth, y1: y(maximum * fraction), y2: y(maximum * fraction), class: 'grid'}));
    const label = svg('text', {x: width, y: y(maximum * fraction) + 4, 'text-anchor': 'end', class: 'tick'});
    label.textContent = numberFormat.format(maximum * fraction);
    root.append(label);
  }
  const hits = [];
  values.forEach((item, index) => {
    const x = left + index * slot + gap / 2;
    const barWidth = Math.max(1, slot - gap);
    const blocked = count(item.blocked);
    const allowed = count(item.allowed);
    const partial = isPartial(item);
    if (partial && !blocked && !allowed) {
      const stub = Math.min(plotHeight * 0.14, 28);
      root.append(svg('rect', {x, width: barWidth, y: y(0) - stub, height: stub, rx: 1.5, class: 'bar-unknown'}));
    }
    if (allowed) root.append(svg('rect', {x, width: barWidth, y: y(blocked + allowed), height: Math.max(0.5, y(blocked) - y(blocked + allowed)), rx: 1.5, class: 'bar-allowed' + (partial ? ' bar-partial' : '')}));
    if (blocked) root.append(svg('rect', {x, width: barWidth, y: y(blocked), height: Math.max(1, y(0) - y(blocked)), rx: 1.5, class: 'bar-blocked' + (partial ? ' bar-partial' : '')}));
    const every = range === 'day' ? 6 : 1;
    const last = index === values.length - 1;
    if (range === 'day' ? (values.length - 1 - index) % every === 0 : true) {
      const tick = svg('text', {x: x + barWidth / 2, y: height - 6, 'text-anchor': last && range === 'day' ? 'end' : 'middle', class: 'tick'});
      tick.textContent = last ? (range === 'day' ? 'now' : (item.kind === 'utc-day' ? 'Today' : 'Today')) : periodLabel(item, true);
      if (last && range === 'day') tick.setAttribute('x', x + barWidth);
      root.append(tick);
    }
    const hit = svg('rect', {x: left + index * slot, y: top, width: slot, height: plotHeight, class: 'hit', tabindex: index === values.length - 1 ? 0 : -1});
    const title = svg('title');
    title.textContent = describe(item);
    hit.setAttribute('role', 'img');
    hit.setAttribute('aria-label', title.textContent);
    hit.append(title);
    hit.addEventListener('pointerenter', () => readout(item, last));
    hit.addEventListener('focus', () => { hits.forEach((node) => node.classList.remove('active')); hit.classList.add('active'); readout(item, last); });
    hit.addEventListener('blur', () => hit.classList.remove('active'));
    hit.addEventListener('keydown', (event) => {
      const step = event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : 0;
      if (!step) return;
      event.preventDefault();
      const next = hits[index + step];
      if (next) { hit.setAttribute('tabindex', '-1'); next.setAttribute('tabindex', '0'); next.focus(); }
    });
    hits.push(hit);
  });
  root.append(svg('line', {x1: left, x2: left + plotWidth, y1: y(0), y2: y(0), class: 'baseline'}));
  hits.forEach((hit) => root.append(hit));
  root.addEventListener('pointerleave', () => readout(null));
  const empty = values.every((item) => !count(item.blocked) && !count(item.allowed));
  chart.replaceChildren(root);
  if (empty) chart.append(element('p', hasHistory() ? 'No connections in this period.' : 'The timeline fills in as connections pass through the proxy.', 'chart-empty'));
  if (blank) $('chart-readout').replaceChildren();
  else readout(null);
  $('range-day').closest('.segmented').hidden = blank;

  $('chart-table').tBodies[0].replaceChildren(...values.map((item) => {
    const row = element('tr');
    const unknown = isPartial(item) && !count(item.blocked) && !count(item.allowed);
    const cell = (value) => unknown ? 'No data' : numberFormat.format(count(value)) + (isPartial(item) ? ' (partial)' : '');
    row.append(element('th', periodLabel(item, false)), element('td', cell(item.blocked)), element('td', cell(item.allowed)));
    row.firstChild.scope = 'row';
    return row;
  }));
}

/* ---------- Breakdown ---------- */

function renderBreakdown(mode) {
  const section = $('breakdown');
  const show = (mode === 'full' || mode === 'aggregate') && hasHistory();
  section.hidden = !show;
  if (!show) return;
  const key = mode === 'full' && range === 'day' ? 'today' : 'week';
  $('breakdown-range').textContent = key === 'today' ? (mode === 'aggregate' ? '· today (UTC)' : '· today') : '· last 7 days';
  const categories = Array.isArray(insights.categories?.[key]) ? insights.categories[key] : [];
  const total = categories.reduce((sum, item) => sum + count(item.blocked), 0);
  const maxCategory = Math.max(1, ...categories.map((item) => count(item.blocked)));
  $('categories').replaceChildren(...categories
    .filter((item) => item.id !== 'other' || count(item.blocked))
    .map((item) => {
      const value = count(item.blocked);
      const row = element('li', null, (item.id === 'threats' && value ? 'threat' : '') + (value ? '' : ' zero'));
      row.append(element('span', categoryLabels[item.id] || item.id, 'name'),
        element('span', numberFormat.format(value) + (total && value ? ' · ' + percentFormat.format(value / total) : ''), 'count'));
      const meter = element('span', null, 'meter');
      const fill = element('span');
      fill.style.setProperty('--w', (value / maxCategory * 100).toFixed(1) + '%');
      meter.append(fill);
      row.append(meter);
      return row;
    }));

  const tops = Array.isArray(insights.top_blocked?.[key]) ? insights.top_blocked[key] : [];
  const maxTop = Math.max(1, ...tops.map((item) => count(item.count)));
  if (!tops.length) {
    $('top-domains').replaceChildren(element('li', 'Nothing blocked in this period.', 'empty-line'));
    return;
  }
  $('top-domains').replaceChildren(...tops.map((item) => {
    const threat = item.category === 'threats';
    const row = element('li', null, threat ? 'threat' : '');
    const name = element('button', item.host, 'name host host-button');
    name.type = 'button';
    name.title = 'Show in activity';
    name.addEventListener('click', () => focusHost(item.host));
    row.append(name, element('span', threat ? 'Threat' : categoryLabels[item.category]?.split(' ')[0] === 'Cloaked' ? 'CNAME' : item.category === 'manual' ? 'Your rule' : '', threat ? 'tag threat' : 'tag'),
      element('span', numberFormat.format(count(item.count)), 'count'));
    const meter = element('span', null, 'meter');
    const fill = element('span');
    fill.style.setProperty('--w', (count(item.count) / maxTop * 100).toFixed(1) + '%');
    meter.append(fill);
    row.append(meter);
    return row;
  }));
}

function focusHost(host) {
  $('hostname').value = host;
  shown = PAGE;
  renderActivity();
  clearLookup();
  $('activity').scrollIntoView({block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'});
  $('hostname').focus({preventScroll: true});
}

/* ---------- Activity ---------- */

function renderActivity() {
  const search = $('hostname').value.trim().toLowerCase();
  const history = activityMeta.history;
  const filtered = events?.filter((event) => (decisionFilter === 'all' || event.decision === decisionFilter)
    && (!search || event.host?.toLowerCase().includes(search))) || [];
  const live = events?.length && history === 'full' ? 'updates every 20 s' : '';
  $('activity-live').textContent = live ? '· ' + live : '';
  const dropped = activityMeta.dropped;
  const summary = !events
    ? 'Recent decisions could not be loaded. Refresh to try again.'
    : history === 'none'
      ? 'History is off, so no activity is kept. You can still check how any domain would be handled.'
      : history === 'aggregate'
        ? 'Daily totals only: blocked domains are kept as a count per UTC day, allowed traffic without hostnames.'
        : events.length ? 'The ' + plural(events.length, 'latest decision', 'latest decisions') + ' from this Mac’s proxy.' : '';
  $('activity-summary').textContent = summary + (dropped ? ' ' + plural(dropped, 'event was', 'events were') + ' not recorded because the ledger was busy.' : '');
  $('activity-summary').hidden = !$('activity-summary').textContent;
  document.querySelector('[data-decision]').closest('.segmented').hidden = history === 'none';
  const message = $('activity-message');
  message.hidden = Boolean(filtered.length) || !events || history === 'none';
  message.textContent = events?.length ? 'No recent decisions match. Press Enter to check this domain.' : 'No activity yet.';
  $('activity-rows').hidden = !filtered.length;
  $('activity-more').hidden = filtered.length <= shown;
  if (!filtered.length) {
    $('activity-rows').replaceChildren();
    return;
  }
  $('activity-rows').replaceChildren(...filtered.slice(0, shown).map(activityRow));
}

function activityRow(event) {
  const row = element('li', null, 'row');
  const category = categoryOf(event.reason);
  const blocked = event.decision === 'blocked';
  const decisionClass = blocked ? (category === 'threats' ? 'decision threat' : 'decision blocked') : 'decision allowed';
  const label = blocked ? 'Blocked' : event.decision === 'allowed' ? 'Allowed' : (event.decision || '—');
  const reason = reasonText(event.reason) + (event.count > 1 ? ' · ×' + numberFormat.format(event.count) : '');
  const cell = element('div', null, 'host-cell');
  const host = event.host ? element('button', event.host, 'host-button') : element('span', 'Allowed traffic (hostnames not kept)', 'reason');
  if (event.host) {
    host.type = 'button';
    host.setAttribute('aria-label', 'Check ' + event.host);
    host.addEventListener('click', () => { $('hostname').value = event.host; renderActivity(); void lookup(); });
  }
  const meta = element('div', null, 'meta');
  meta.append(element('span', label, decisionClass), element('span', '· ' + reason), document.createTextNode('·'), timeNode(event.at, event.day_only));
  cell.append(host, meta);
  const when = element('span', null, 'when');
  when.append(timeNode(event.at, event.day_only));
  const act = element('span', null, 'act');
  const action = rowAction(event, category);
  if (action) act.append(action);
  row.append(element('span', label, decisionClass), cell, element('span', reason, 'reason'), when, act);
  return row;
}

function rowAction(event, category) {
  const c = controls();
  if (!event.host || !writable()) return null;
  let action = null;
  let text = '';
  if (event.decision === 'blocked' && (category === 'ads' || category === 'cname') && durationOptions(c.allow_minutes).length) {
    action = 'allow'; text = 'Allow…';
  } else if (event.decision === 'blocked' && category === 'manual' && c.unblock === true) {
    action = 'unblock'; text = 'Unblock…';
  } else if (event.decision === 'allowed' && c.block === true) {
    action = 'block'; text = 'Block…';
  }
  if (!action) return null;
  const button = element('button', text, 'button quiet small');
  button.type = 'button';
  button.setAttribute('aria-label', text.replace('…', '') + ' ' + event.host);
  button.addEventListener('click', () => void guardedAction(action, event.host, button));
  return button;
}

async function guardedAction(action, host, button) {
  // Ask the policy first so the dialog never offers something the service would refuse.
  button.disabled = true;
  try {
    const result = await api('/api/domain?' + new URLSearchParams({host}));
    const allowed = action === 'allow' ? result.can_allow : action === 'block' ? result.can_block : result.can_unblock;
    if (!allowed) {
      notice('notification', action === 'allow' ? host + ' is blocked by a rule that cannot be bypassed here.' : host + ' cannot be changed from the dashboard.', true);
      return;
    }
    openAction(action, result.host || host);
  } catch (error) {
    if (!authExpired && error.name !== 'AbortError') notice('notification', error.message, true);
  } finally {
    button.disabled = false;
  }
}

function renderExceptions(rows, removable) {
  if ($('temporary-allows').contains(document.activeElement)) return;
  if (!changed('exceptions', [rows, removable])) return;
  $('exceptions').hidden = !Array.isArray(rows) || !rows.length;
  if ($('exceptions').hidden) {
    $('temporary-allows').replaceChildren();
    return;
  }
  $('temporary-allows').replaceChildren(...rows.map((item) => {
    const row = element('li');
    const details = element('div');
    const expires = formattedDate(item.expires_at, hourFormat);
    details.append(element('span', item.host, 'host'), document.createTextNode(' '), element('span', expires ? 'until ' + expires : ''));
    row.append(details);
    if (removable) {
      const remove = element('button', 'Remove', 'button quiet small');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'Remove temporary allow for ' + item.host);
      remove.addEventListener('click', () => openAction('remove_allow', item.host));
      row.append(remove);
    }
    return row;
  }));
}

/* ---------- Domain check ---------- */

function renderLookupActions(container) {
  const c = controls();
  const buttons = [];
  const add = (id, label, action) => {
    const button = element('button', label, 'button quiet small');
    button.type = 'button';
    button.id = id;
    button.addEventListener('click', () => openAction(action, lookupResult?.host));
    buttons.push(button);
  };
  if (lookupResult?.can_allow && lookupResult.decision === 'blocked' && durationOptions(c.allow_minutes).length) add('allow', 'Allow temporarily…', 'allow');
  if (lookupResult?.can_block && c.block === true) add('block', 'Block domain…', 'block');
  if (lookupResult?.can_unblock && c.unblock === true) add('unblock', 'Remove my block…', 'unblock');
  if (!buttons.length) return;
  const group = element('div', null, 'button-group');
  group.append(...buttons);
  container.append(group);
}

function clearLookup() {
  lookupController?.abort();
  lookupController = null;
  lookupResult = null;
  $('lookup-result').hidden = true;
  $('lookup-result').replaceChildren();
}

async function lookup() {
  const host = $('hostname').value.trim();
  clearLookup();
  const result = $('lookup-result');
  result.hidden = false;
  if (!host || /[\s/:?#@]/.test(host)) {
    result.append(element('p', 'Enter a hostname such as example.com.', 'error'));
    return;
  }
  const controller = new AbortController();
  lookupController = controller;
  result.append(element('p', 'Checking policy…'));
  try {
    const returned = await api('/api/domain?' + new URLSearchParams({host}), {signal: AbortSignal.any([controller.signal, AbortSignal.timeout(20000)])});
    if (lookupController !== controller) return;
    lookupResult = returned;
    const expires = formattedDate(returned.expires_at);
    result.replaceChildren(element('span', returned.host || host, 'host'), badge(returned.decision));
    const source = returned.reason || returned.source;
    const why = element('p', (returned.decision === 'blocked' ? 'Would be blocked: ' : returned.decision === 'allowed' ? 'Would be allowed: ' : '') + reasonText(source).toLowerCase() + '.');
    result.append(why);
    if (expires) result.append(element('p', 'Temporary allow expires ' + expires + '.'));
    renderLookupActions(result);
  } catch (error) {
    if (lookupController === controller && error.name !== 'AbortError') result.replaceChildren(element('p', error.message, 'error'));
  }
}

/* ---------- Refresh ---------- */

async function refresh(manual = false) {
  if (authExpired || submitting) return;
  if (refreshPromise) return refreshPromise;
  if (manual) $('refresh').disabled = true;

  refreshPromise = (async () => {
    const loaded = await Promise.allSettled([api('/api/status'), api('/api/activity'), api('/api/insights')]);
    if (authExpired) return;
    const [snapshot, activity, summary] = loaded;
    $('dashboard').hidden = false;
    $('refresh').hidden = false;
    if (snapshot.status === 'fulfilled') {
      status = snapshot.value;
      notice('connection', '');
    } else {
      status = null;
      notice('connection', snapshot.reason.message, true);
    }
    renderHealth();
    renderExceptions(status?.temporary_allows, controls().remove_allow === true);
    insights = summary.status === 'fulfilled' && summary.value && typeof summary.value === 'object' ? summary.value : null;
    renderOutcome();
    if (!$('activity-rows').contains(document.activeElement)) {
      const next = activity.status === 'fulfilled' && activity.value.available !== false && Array.isArray(activity.value.events) ? activity.value.events : null;
      const value = activity.status === 'fulfilled' ? activity.value : {};
      const meta = {history: ['aggregate', 'none'].includes(value.history) ? value.history : 'full', dropped: Number.isInteger(value.dropped) && value.dropped > 0 ? value.dropped : 0};
      // Relative times age, so the list re-renders each refresh even when rows are unchanged.
      events = next;
      activityMeta = meta;
      renderActivity();
    }
    document.body.dataset.ready = '1';
  })();

  try {
    await refreshPromise;
  } finally {
    refreshPromise = null;
    $('refresh').disabled = false;
  }
}

/* ---------- Actions ---------- */

function actionDetails(action, host) {
  const c = status.controls || {};
  switch (action) {
    case 'pause':
      return ['Pause ad filtering?', 'Ads and trackers on proxy connections can load until filtering resumes. Malware and phishing filtering stays on.', 'Pause filtering', durationOptions(c.pause_minutes)];
    case 'resume':
      return ['Resume ad filtering?', 'The proxy will apply its ad and tracker filters immediately.', 'Resume filtering'];
    case 'allow':
      return ['Allow ' + host + ' for a while?', host + ' will skip the ad and tracker lists until the time runs out. Only this hostname is affected; threat filtering still applies.', 'Allow domain', durationOptions(c.allow_minutes)];
    case 'remove_allow':
      return ['Remove this temporary allow?', 'Normal filter rules will apply to ' + host + ' immediately.', 'Remove exception'];
    case 'block':
      return ['Block ' + host + '?', 'The proxy will block ' + host + ' and its subdomains until you remove the block.', 'Block domain'];
    case 'unblock':
      return ['Remove your block on ' + host + '?', 'The proxy will evaluate ' + host + ' against the remaining rules.', 'Remove block'];
    case 'refresh_filters':
      return ['Refresh filter feeds?', 'The service will check its configured sources for updated domain lists.', 'Refresh feeds'];
    case 'pause_canaries':
      return ['Pause canary alerts for 15 minutes?', 'Alerts will be muted for 15 minutes. The monitor will continue recording events.', 'Pause alerts'];
    case 'resume_canaries':
      return ['Resume canary alerts?', 'The monitor will show notifications for new events immediately.', 'Resume alerts'];
    default:
      return null;
  }
}

function openAction(action, host) {
  if (!writable() || submitting) return;
  const details = actionDetails(action, host);
  if (!details) return;
  const [title, detail, label, options] = details;
  if (options && !options.length) return;
  actionRequest = {action};
  if (host) actionRequest.host = host;
  if (action === 'pause_canaries') actionRequest.minutes = 15;
  if (options) {
    $('duration').replaceChildren(...options.map((minutes) => {
      const option = element('option', minutes + ' minutes');
      option.value = minutes;
      return option;
    }));
  }
  $('confirm-title').textContent = title;
  $('confirm-detail').textContent = detail;
  $('confirm-action').textContent = label;
  $('duration-control').hidden = !options;
  notice('notification', '');
  notice('action-status', '');
  $('confirm').showModal();
}

async function submitAction(event) {
  event.preventDefault();
  if (submitting || !actionRequest) return;
  if (!writable()) {
    notice('action-status', 'Refresh protection status before trying again.', true);
    return;
  }
  const payload = {...actionRequest};
  if (!$('duration-control').hidden) payload.minutes = Number($('duration').value);
  submitting = true;
  $('cancel').disabled = true;
  $('confirm-action').disabled = true;
  $('duration').disabled = true;
  notice('action-status', 'Applying change…');

  try {
    const result = await api('/api/action', {
      method: 'POST',
      signal: AbortSignal.timeout(30000),
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': status.csrf_token},
      body: JSON.stringify(payload),
    });
    $('confirm').close();
    if (payload.action === 'remove_allow') $('exceptions-title').focus();
    notice('notification', result.message || 'Change applied.');
    if (lookupResult) void lookup();
  } catch (error) {
    if (!authExpired) notice('action-status', error.message, true);
  } finally {
    submitting = false;
    $('cancel').disabled = false;
    $('confirm-action').disabled = false;
    $('duration').disabled = false;
    if (!authExpired) {
      await refreshPromise;
      await refresh();
    }
  }
}

/* ---------- Wiring ---------- */

$('refresh').addEventListener('click', () => void refresh(true));
$('health-toggle').addEventListener('click', () => {
  detailTouched = true;
  setDetail($('health-detail').hidden);
});
$('lookup').addEventListener('submit', (event) => {
  event.preventDefault();
  void lookup();
});
$('hostname').addEventListener('input', () => {
  clearLookup();
  shown = PAGE;
  renderActivity();
});
for (const button of document.querySelectorAll('[data-decision]')) {
  button.addEventListener('click', () => {
    decisionFilter = button.dataset.decision;
    for (const other of document.querySelectorAll('[data-decision]')) other.setAttribute('aria-pressed', String(other === button));
    shown = PAGE;
    renderActivity();
  });
}
for (const [id, value] of [['range-day', 'day'], ['range-week', 'week']]) {
  $(id).addEventListener('click', () => {
    if ($(id).disabled) return;
    range = value;
    renderOutcome();
  });
}
$('activity-more').addEventListener('click', () => { shown += PAGE * 2; renderActivity(); });
$('cancel').addEventListener('click', () => $('confirm').close());
$('confirm').addEventListener('cancel', (event) => {
  if (submitting) event.preventDefault();
});
$('confirm-form').addEventListener('submit', (event) => void submitAction(event));
for (const id of ['pause', 'resume', 'refresh-filters', 'pause-canaries', 'resume-canaries']) {
  $(id).addEventListener('click', () => openAction(id.replaceAll('-', '_')));
}
$('chart').addEventListener('focusout', (event) => {
  if (!chartPending || $('chart').contains(event.relatedTarget)) return;
  chartPending = false;
  window.setTimeout(() => {
    if (!$('chart').contains(document.activeElement) && insights) renderTimeline(historyMode());
  }, 0);
});
let resizeFrame = 0;
new ResizeObserver(() => {
  cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(() => {
    if (!insights) return;
    records.delete('outcome');
    renderOutcome();
  });
}).observe($('chart'));

async function initialize() {
  const fragment = window.location.hash.slice(1);
  if (/^[A-Za-z0-9_-]{43}$/.test(fragment)) {
    window.history.replaceState(null, '', window.location.pathname);
    try {
      const session = await api('/api/session', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({token: fragment}),
      });
      if (!/^[A-Za-z0-9_-]{43}$/.test(session.session_token || '')) throw new Error('The local session could not be established.');
      bearer = session.session_token;
      try { sessionStorage.setItem('egress-guard.session', bearer); } catch {}
    } catch (error) {
      expiredSession();
      return;
    }
  }
  await refresh();
  window.setInterval(() => {
    if (document.visibilityState === 'visible') void refresh();
  }, 20000);
}

void initialize();
