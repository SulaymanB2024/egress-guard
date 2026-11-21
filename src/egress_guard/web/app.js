'use strict';

const $ = (id) => document.getElementById(id);
const hourFormat = new Intl.DateTimeFormat(undefined, {hour: '2-digit', minute: '2-digit', hourCycle: 'h23'});
const timeFormat = new Intl.DateTimeFormat(undefined, {hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'});
const dayFormat = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric'});
const weekdayFormat = new Intl.DateTimeFormat(undefined, {weekday: 'short'});
const utcDayFormat = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric', timeZone: 'UTC'});
const utcWeekdayFormat = new Intl.DateTimeFormat(undefined, {weekday: 'short', timeZone: 'UTC'});
const dateFormat = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'});
const numberFormat = new Intl.NumberFormat();
const PAGE = 15;

// Check states: [word, state] where state is one of the design system's states (DESIGN.md section 4).
const stateLabels = {
  active: ['On', 'protected'], admin_required: ['Needs admin', 'reduced'], allowed: ['Allowed', 'protected'],
  degraded: ['Needs attention', 'reduced'], disabled: ['Off', 'neutral'], down: ['Off', 'unprotected'],
  enabled: ['On', 'protected'], failed: ['Failed', 'unprotected'], fresh: ['Current', 'protected'],
  healthy: ['On', 'protected'], installed: ['Installed', 'protected'], maintenance_blocked: ['Deferred', 'reduced'], observed: ['Observed', 'neutral'],
  offline: ['Off', 'unprotected'], ok: ['OK', 'protected'], paused: ['Paused', 'reduced'],
  pending: ['Pending', 'reduced'], ready: ['Ready', 'protected'], restart_required: ['Needs restart', 'reduced'], stale: ['Stale', 'reduced'],
  unavailable: ['Unavailable', 'neutral'], unknown: ['Not checked', 'neutral'],
};
// Ledger block sources in plain language. Unknown values are shown as recorded.
const reasons = {
  'tracker-feed': 'Ad or tracker list', tracker: 'Ad or tracker list', ads: 'Ad or tracker list',
  'cname-feed': 'Cloaked tracker (CNAME)', 'cname-cloak': 'Cloaked tracker (CNAME)',
  'threat-intel': 'Threat intelligence', malware: 'Malware', phishing: 'Phishing',
  'local-block': 'Your block rule', 'local-allow': 'Your allow rule', 'temporary-exception': 'Temporarily allowed',
  'tracker-paused': 'Ad filtering paused', 'dashboard-exception': 'Exempt dashboard host', 'no-match': 'No rule matched',
  'plaintext-credentials': 'Password sent unencrypted', 'not-ready': 'Filters not ready', 'non-tls-tunnel': 'Non-TLS tunnel refused',
  'invalid-host': 'Malformed hostname', 'invalid-request': 'Malformed request', doh: 'Encrypted DNS server',
  'malware-feed': 'Malware list', 'phishing-feed': 'Phishing list', 'lookalike-domain': 'Look-alike domain',
  'doh-feed': 'Encrypted DNS server', 'safety-list': 'Built-in safety list',
  'ip-literal': 'Direct IP address (not filtered)', 'nonstandard-port': 'Unusual port (not filtered)',
};
const sourceCategory = {
  'threat-intel': 'threats', malware: 'threats', phishing: 'threats',
  'malware-feed': 'threats', 'phishing-feed': 'threats', 'lookalike-domain': 'threats', 'doh-feed': 'doh', doh: 'doh',
  'tracker-feed': 'ads', tracker: 'ads', ads: 'ads', 'cname-feed': 'cname', 'cname-cloak': 'cname', 'local-block': 'manual',
};
const categoryLabels = {threats: 'Threats', ads: 'Ads and trackers', cname: 'Cloaked trackers', doh: 'Encrypted DNS servers', manual: 'Your rules', other: 'Other'};
const categoryWords = {threats: 'Threat', ads: 'Ad or tracker', cname: 'Cloaked tracker', doh: 'Encrypted DNS server', manual: 'Your rule', other: 'Other'};

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
let toastTimer = 0;
let bearer = '';
try { bearer = sessionStorage.getItem('egress-guard.session') || ''; } catch {}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function list(value) {
  return Array.isArray(value) ? value : [];
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

function percent(fraction) {
  const digits = fraction > 0 && fraction < 0.01 ? 1 : 0;
  return new Intl.NumberFormat(undefined, {style: 'percent', maximumFractionDigits: digits}).format(fraction);
}

function ago(value) {
  const parsed = date(value);
  if (!parsed) return '';
  const seconds = Math.max(0, (Date.now() - parsed.getTime()) / 1000);
  if (seconds < 45) return 'just now';
  if (seconds < 3600) return Math.max(1, Math.round(seconds / 60)) + ' min ago';
  if (seconds < 86400) return Math.round(seconds / 3600) + ' h ago';
  return dayFormat.format(parsed);
}

function age(value) {
  const seconds = Math.max(0, (Date.now() - value.getTime()) / 1000);
  if (seconds < 3600) return Math.max(1, Math.round(seconds / 60)) + ' min';
  if (seconds < 172800) return Math.round(seconds / 3600) + ' h';
  return Math.round(seconds / 86400) + ' days';
}

function timeNode(value, dayOnly) {
  const parsed = date(value);
  if (!parsed) return element('span', '—');
  const today = parsed.toISOString().slice(0, 10) === new Date().toISOString().slice(0, 10);
  const node = element('time', dayOnly ? (today ? 'today' : utcDayFormat.format(parsed)) : ago(parsed));
  node.dateTime = parsed.toISOString();
  node.title = dayOnly ? utcDayFormat.format(parsed) + ' (UTC day)' : dateFormat.format(parsed) + ' · ' + timeFormat.format(parsed);
  return node;
}

function reasonText(source) {
  return Object.hasOwn(reasons, source) ? reasons[source] : (typeof source === 'string' && source ? source : '—');
}

function categoryOf(source) {
  // The service derives this from its policy table; the built-in table covers a page that has no insights yet.
  const served = insights?.source_categories;
  if (served && typeof served === 'object' && Object.hasOwn(served, source)) return served[source];
  return Object.hasOwn(sourceCategory, source) ? sourceCategory[source] : 'other';
}

function stateWord(state) {
  const [word, tone] = Object.hasOwn(stateLabels, state) ? stateLabels[state] : stateLabels.unknown;
  const node = element('span', null, 'state-word');
  node.dataset.state = tone;
  const dot = element('span', null, tone === 'neutral' ? 'dot hollow' : 'dot');
  dot.setAttribute('aria-hidden', 'true');
  node.append(dot, element('span', word, 'word'));
  return node;
}

/* ---------- Fitting text (DESIGN.md section 8) ---------- */

const measure = document.createElement('canvas').getContext('2d');

function fitHost(host, fits) {
  // Middle truncation by whole labels: keep the registrable domain, add labels back from the left.
  if (fits(host)) return host;
  const labels = host.split('.');
  const keep = labels.length > 2 && labels.at(-1).length === 2 && /^(co|com|org|net|ac|gov|edu)$/.test(labels.at(-2)) ? 3 : 2;
  const tail = labels.slice(-keep).join('.');
  const head = [];
  for (const label of labels.slice(0, -keep)) {
    if (!fits([...head, label].join('.') + '.….' + tail)) break;
    head.push(label);
  }
  if (head.length) return head.join('.') + '.….' + tail;
  if (labels.length > keep && fits('….' + tail)) return '….' + tail;
  for (let size = tail.length - 1; size > 1; size -= 1) {
    const front = Math.ceil(size / 2);
    const cut = tail.slice(0, front) + '…' + tail.slice(tail.length - (size - front));
    if (fits(cut)) return cut;
  }
  return '…';
}

function fitEnd(text, fits) {
  if (fits(text)) return text;
  let low = 0, high = text.length;
  while (low < high) {
    const middle = Math.ceil((low + high) / 2);
    if (fits(text.slice(0, middle).trimEnd() + '…')) low = middle; else high = middle - 1;
  }
  return text.slice(0, low).trimEnd() + '…';
}

function fit(node) {
  const full = node.dataset.full;
  const width = node.clientWidth;
  if (full == null || !width) return;
  const style = getComputedStyle(node);
  measure.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
  const fits = (text) => measure.measureText(text).width <= width - 1;
  const text = node.dataset.fit === 'host' ? fitHost(full, fits) : fitEnd(full, fits);
  if (node.textContent !== text) node.textContent = text;
  if (text === full) node.removeAttribute('title'); else node.title = full;
}

function fitAll(root = document) {
  for (const node of root.querySelectorAll('[data-fit]')) fit(node);
}

function fitted(tag, text, kind, className) {
  const node = element(tag, text, className);
  node.dataset.full = text;
  node.dataset.fit = kind;
  return node;
}

/* ---------- Messages ---------- */

function notice(id, message, isError = false) {
  if (id === 'notification' && message && !isError) {
    // Confirms an action that changed something out of view; errors stay in place instead.
    $('notification').hidden = true;
    $('toast').textContent = message;
    $('toast').hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { $('toast').hidden = true; }, 4000);
    return;
  }
  const node = $(id);
  node.textContent = message;
  node.hidden = !message;
  node.classList.toggle('inline-error', isError);
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
  for (const id of ['activity-rows', 'proxies', 'canaries', 'filters', 'maintenance', 'security', 'temporary-allows', 'categories', 'top-domains', 'bars', 'axis', 'threat-list']) {
    $(id).replaceChildren();
  }
  bars = [];
  $('dashboard').hidden = true;
  $('health-detail').hidden = true;
  $('refresh').hidden = true;
  for (const id of ['pause', 'resume', 'refresh-filters', 'health-toggle']) $(id).hidden = true;
  $('confirm').close();
  $('hostname').value = '';
  setStatus('neutral', 'Signed out', '', true);
  notice('notification', '');
  $('signed-out').hidden = false;
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

/* ---------- Status row and details ---------- */

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

function footprintText() {
  const footprint = status?.footprint;
  if (!footprint || typeof footprint !== 'object') return '';
  const parts = [];
  if (Number.isFinite(footprint.rss_bytes)) parts.push(bytes(footprint.rss_bytes) + ' memory');
  if (Number.isFinite(footprint.uptime_seconds)) parts.push('up ' + age(new Date(Date.now() - footprint.uptime_seconds * 1000)));
  return parts.join(' · ');
}

function setStatus(tone, word, fact, hollow) {
  $('status').dataset.state = tone;
  $('status').querySelector('.dot').className = hollow ? 'dot hollow' : 'dot';
  $('status-word').textContent = word;
  $('status-fact').textContent = fact;
}

function feedsReady(filters) {
  return filters.length && !filters.some((item) => item.detail === 'missing');
}

function renderHealth() {
  const protection = status?.protection || {};
  const state = ['active', 'paused', 'degraded'].includes(protection.state) ? protection.state : 'unknown';
  const filters = list(status?.filters);
  const proxies = list(status?.proxies);
  const proxyUp = proxies[0]?.state === 'active';
  const policy = proxies[1];
  const stale = filters.filter((item) => item.state !== 'active');
  const c = controls();
  let needsLists = false;

  if (!status) {
    setStatus('neutral', 'Unknown', 'The protection service did not answer', true);
  } else if (state === 'degraded' || state === 'unknown') {
    const ready = feedsReady(filters);
    const causes = [];
    if (!ready) causes.push('block lists not downloaded');
    if (!proxyUp) causes.push('proxy not running');
    if (ready && proxyUp) causes.push('saved rules not applied yet');
    const fact = causes.join(' · ');
    setStatus('unprotected', 'Not protecting', fact.charAt(0).toUpperCase() + fact.slice(1));
    needsLists = !ready;
  } else if (state === 'paused') {
    const until = formattedDate(protection.pause_expires_at, hourFormat);
    setStatus('reduced', 'Paused', (until ? 'Ad filtering resumes at ' + until : 'Ad filtering resumes automatically') + ' · threats still blocked');
  } else if (stale.length) {
    const oldest = stale.map((item) => date(item.updated_at)).filter(Boolean).sort((a, b) => a - b)[0];
    const lists = plural(stale.length, 'block list', 'block lists');
    const verb = stale.length === 1 ? ' is ' : ' are ';
    setStatus('reduced', 'Reduced', lists + verb + (oldest ? age(oldest) + ' old' : 'out of date'));
    needsLists = true;
  } else if (policy && policy.state !== 'active') {
    setStatus('reduced', 'Reduced', 'Saved rules are not applied yet');
  } else {
    const updated = filters.map((item) => date(item.updated_at)).filter(Boolean).sort((a, b) => a - b)[0];
    setStatus('protected', 'Protected', 'Filtering apps on the proxy' + (updated ? ' · lists updated ' + ago(updated) : ''));
  }

  $('pause').hidden = state !== 'active' || !durationOptions(c.pause_minutes).length;
  $('resume').hidden = c.resume !== true;
  $('refresh-filters').hidden = !needsLists || c.refresh_filters !== true;
  $('refresh-filters-detail').hidden = !$('refresh-filters').hidden || c.refresh_filters !== true;
  $('pause-canaries').hidden = c.pause_canaries !== true;
  $('resume-canaries').hidden = c.resume_canaries !== true;
  $('health-toggle').hidden = !status;

  // Calm when fine; open with numbered steps when protection is not running.
  if (!detailTouched) setDetail(Boolean(status) && (state === 'degraded' || state === 'unknown'));
  renderSetup(state, filters, proxyUp);
  const proxyRows = proxies.map((item, index) => index === 0 && footprintText()
    ? {...item, detail: [item.detail, footprintText()].filter(Boolean).join(' · ')} : item);
  renderChecks('proxies', status ? proxyRows : null);
  for (const id of ['canaries', 'filters', 'maintenance', 'security']) renderChecks(id, status?.[id]);
  $('security-section').hidden = !Array.isArray(status?.security) || !status.security.length;
}

function setDetail(open) {
  $('health-detail').hidden = !open;
  $('health-toggle').setAttribute('aria-expanded', String(open));
  if (open) fitAll($('health-detail'));
}

function renderSetup(state, filters, proxyUp) {
  const steps = [];
  if (status && (state === 'degraded' || state === 'unknown')) {
    if (!feedsReady(filters)) steps.push(['Download the block lists: ', 'egress-guard refresh']);
    if (!proxyUp) steps.push(['Start the proxy: ', 'egress-guard start']);
    steps.push(['Set an app or browser to use the HTTP proxy ', '127.0.0.1:' + (proxyPort() || '…'), ' for HTTP and HTTPS.']);
  }
  if (!changed('setup', steps)) return;
  $('setup').hidden = !steps.length;
  $('setup').replaceChildren(...steps.map(([lead, code, tail]) => {
    const item = element('li');
    const text = element('span', lead);
    text.append(element('code', code, 'host'));
    if (tail) text.append(tail);
    item.append(text);
    return item;
  }));
}

function renderChecks(id, rows) {
  if (!changed(id, rows)) return;
  if (!Array.isArray(rows) || !rows.length) {
    $(id).replaceChildren(element('li', 'Nothing reported.', 'muted check-none'));
    return;
  }
  $(id).replaceChildren(...rows.map((item) => {
    const li = element('li');
    const row = element('div', null, 'row check');
    const main = element('div', null, 'main');
    const entries = Number.isSafeInteger(item.entries) && item.entries > 0 ? plural(item.entries, 'domain', 'domains') : '';
    const published = formattedDate(item.published_at, dayFormat);
    const updated = item.updated_at ? 'downloaded ' + ago(item.updated_at) : '';
    const checked = item.checked_at ? 'checked ' + ago(item.checked_at) : '';
    const detail = item.detail === 'current' ? '' : item.detail;
    const line2 = [detail, entries, published && 'published ' + published, updated, checked].filter(Boolean).join(' · ');
    main.append(fitted('div', item.name || 'Check', 'end', 'line1'));
    if (line2) main.append(element('div', line2, 'line2'));
    const trail = element('span', null, 'trail');
    trail.append(stateWord(id === 'filters' && item.state === 'degraded' ? (item.detail === 'missing' ? 'unavailable' : 'stale') : id === 'filters' && item.state === 'active' ? 'fresh' : item.state));
    row.append(main, trail);
    li.append(row);
    return li;
  }));
  if (!$('health-detail').hidden) fitAll($(id));
}

/* ---------- Focal block ---------- */

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
  if (!changed('outcome', [stable, range, status?.protection?.state])) return;
  const mode = historyMode();
  const today = insights?.today;
  const data = Boolean(mode && mode !== 'none' && hasHistory());
  $('hero').hidden = !data;
  $('reasons').hidden = !data;
  $('hero-empty').hidden = data;
  $('hero-number').classList.remove('skeleton');

  if (!insights || !mode) {
    $('empty-title').textContent = 'History unavailable';
    $('empty-text').textContent = insights?.message || 'Local history could not be read. Filtering is not affected.';
  } else if (mode === 'none') {
    $('empty-title').textContent = 'History is off';
    const text = $('empty-text');
    text.replaceChildren('Filtering still runs, but nothing is written to disk. To count what is blocked, set ',
      element('code', 'history = "aggregate"', 'host'), ' or ', element('code', 'history = "full"', 'host'),
      ' under ', element('code', '[logging]', 'host'), ' in config.toml.');
  } else if (!data) {
    $('empty-title').textContent = 'No connections yet';
    $('empty-text').textContent = status?.protection?.state === 'degraded'
      ? 'Counts start when the steps above are done and an app goes online through the proxy.'
      : 'Counts start when an app on this Mac goes online through the proxy.';
  } else {
    const blocked = count(today?.blocked);
    const total = blocked + count(today?.allowed);
    $('hero-number').textContent = numberFormat.format(blocked);
    $('hero-label').textContent = mode === 'aggregate' ? 'blocked today (UTC)' : 'blocked today';
    const share = total ? percent(blocked / total) + ' of ' + plural(total, 'connection', 'connections') : 'no connections yet today';
    $('hero-sub').textContent = share + ' · ' + change(mode, blocked);
    const basis = insights.same_time_yesterday;
    $('hero-sub').title = mode === 'full' && basis?.complete !== false ? numberFormat.format(count(basis?.blocked)) + ' blocked by this time yesterday' : '';
    renderReasons();
  }
  renderTimeline(mode, data);
  renderBreakdown(mode, data);
  renderThreats(mode, data);
}

function change(mode, blocked) {
  // Full history compares with the same elapsed time yesterday; aggregate only has whole days.
  const basis = mode === 'full' ? insights.same_time_yesterday : insights.yesterday;
  if (!basis || basis.complete === false) return 'no data for yesterday';
  const previous = count(basis.blocked);
  if (mode === 'aggregate') return numberFormat.format(previous) + ' yesterday';
  if (!previous) return blocked ? 'none by this time yesterday' : 'same as this time yesterday';
  const delta = (blocked - previous) / previous;
  if (Math.abs(delta) < 0.005) return 'same as this time yesterday';
  return (delta > 0 ? 'up ' : 'down ') + percent(Math.abs(delta)) + ' on this time yesterday';
}

function categoryCounts(key) {
  const counts = {};
  for (const item of list(insights?.categories?.[key])) counts[item.id] = count(item.blocked);
  return counts;
}

function renderReasons() {
  const counts = categoryCounts('today');
  const threats = counts.threats || 0;
  $('count-threats').textContent = numberFormat.format(threats);
  $('label-threats').textContent = threats === 1 ? 'threat stopped' : 'threats stopped';
  // A stopped threat is the most important event on the page: its count carries the threat state.
  if (threats) $('count-threats').dataset.state = 'threat'; else delete $('count-threats').dataset.state;
  $('count-ads').textContent = numberFormat.format(counts.ads || 0);
  $('count-cname').textContent = numberFormat.format(counts.cname || 0);
  $('count-manual').textContent = numberFormat.format(counts.manual || 0);
}

/* ---------- Bar strip: built once per range, updated in place on every poll ---------- */

let bars = [];
let chartValues = [];
let chartFact = '';

function series(mode) {
  if (mode === 'full' && range === 'day') return list(insights?.hourly).map((item) => ({...item, kind: 'hour'}));
  return list(insights?.daily).map((item) => ({...item, kind: mode === 'aggregate' ? 'utc-day' : 'day'}));
}

function periodLabel(item, short) {
  const start = date(item.start);
  if (!start) return '';
  if (item.kind === 'hour') return short ? hourFormat.format(start) : hourFormat.format(start) + '–' + hourFormat.format(new Date(start.getTime() + 3600000));
  const weekday = item.kind === 'utc-day' ? utcWeekdayFormat : weekdayFormat;
  const day = item.kind === 'utc-day' ? utcDayFormat : dayFormat;
  return short ? weekday.format(start) : weekday.format(start) + ' ' + day.format(start) + (item.kind === 'utc-day' ? ' (UTC)' : '');
}

function noData(item) {
  return item?.complete === false && !count(item.blocked) && !count(item.allowed);
}

function describe(item, last) {
  if (noData(item)) return periodLabel(item, false) + ': no data recorded';
  const blocked = count(item.blocked);
  return periodLabel(item, false) + (last ? ' (so far)' : '') + ': ' + numberFormat.format(blocked) + ' blocked of '
    + numberFormat.format(blocked + count(item.allowed)) + (item.complete === false ? ' (partial)' : '');
}

function showFact(text) {
  if ($('chart-fact').textContent !== text) $('chart-fact').textContent = text;
}

function buildBars(length) {
  bars = Array.from({length}, (_, index) => {
    const slot = element('span', null, 'slot');
    slot.setAttribute('role', 'img');
    slot.tabIndex = index === length - 1 ? 0 : -1;
    slot.append(element('i'));
    slot.addEventListener('pointerenter', () => showFact(describe(chartValues[index], index === length - 1)));
    slot.addEventListener('pointerleave', () => { if (document.activeElement !== slot) showFact(chartFact); });
    slot.addEventListener('focus', () => showFact(describe(chartValues[index], index === length - 1)));
    slot.addEventListener('blur', () => showFact(chartFact));
    slot.addEventListener('keydown', (event) => {
      const target = {ArrowLeft: index - 1, ArrowRight: index + 1, Home: 0, End: length - 1}[event.key];
      if (target == null) return;
      event.preventDefault();
      const next = bars[Math.max(0, Math.min(length - 1, target))];
      for (const other of bars) other.tabIndex = other === next ? 0 : -1;
      next.focus();
    });
    return slot;
  });
  $('bars').replaceChildren(...bars);
}

function renderTimeline(mode, data) {
  $('range').hidden = mode !== 'full';
  if (mode !== 'full') range = 'week';
  $('range-day').setAttribute('aria-pressed', String(range === 'day'));
  $('range-week').setAttribute('aria-pressed', String(range === 'week'));
  if (!data) return;
  const values = series(mode);
  const hourly = values[0]?.kind === 'hour';
  const title = hourly ? 'Blocked per hour, last 24 hours' : 'Blocked per day, last 7 days' + (mode === 'aggregate' ? ' (UTC)' : '');
  $('chart-title').textContent = title;
  if (bars.length !== values.length) buildBars(values.length);
  chartValues = values;
  const peak = Math.max(0, ...values.map((item) => count(item.blocked)));
  values.forEach((item, index) => {
    const slot = bars[index];
    const bar = slot.firstChild;
    const blocked = count(item.blocked);
    const last = index === values.length - 1;
    bar.className = noData(item) ? 'nodata' : !blocked ? 'zero' : last ? 'now' : '';
    bar.style.setProperty('--h', blocked && peak ? (blocked / peak * 100).toFixed(1) + '%' : '0%');
    const label = describe(item, last);
    if (slot.getAttribute('aria-label') !== label) { slot.setAttribute('aria-label', label); slot.title = label; }
  });
  const peakIndex = values.findIndex((item) => count(item.blocked) === peak);
  const firstData = values.findIndex((item) => !noData(item));
  if (firstData < 0) chartFact = 'No data recorded';
  else if (firstData > 0) chartFact = 'No data before ' + (hourly ? periodLabel(values[firstData], true) : dayFormat.format(date(values[firstData].start)));
  else if (!peak) chartFact = 'None blocked';
  else chartFact = 'Peak ' + numberFormat.format(peak) + (hourly ? ' at ' : ' on ') + periodLabel(values[peakIndex], true);
  if (!$('bars').contains(document.activeElement)) showFact(chartFact);
  $('bars').setAttribute('aria-label', title + ', ' + chartFact.charAt(0).toLowerCase() + chartFact.slice(1) + '. Arrow keys read each ' + (hourly ? 'hour.' : 'day.'));

  // Axis: four or five labels at their bars' columns; the last is always "Now" or "Today".
  const marks = hourly ? [0, 6, 12, 18, values.length - 1] : values.map((_, index) => index);
  if (changed('axis', [values.map((item) => item.start), hourly])) {
    $('axis').style.setProperty('--n', String(values.length));
    $('axis').replaceChildren(...marks.map((index, position) => {
      const last = index === values.length - 1;
      const node = element('span', last ? (hourly ? 'Now' : 'Today') : periodLabel(values[index], true), position === 0 ? 'first' : last ? 'last' : '');
      node.style.setProperty('grid-column', String(index + 1));
      node.style.setProperty('grid-row', '1');
      return node;
    }));
    $('chart-caption').textContent = title;
  }
  $('chart-table').tBodies[0].replaceChildren(...values.map((item) => {
    const row = element('tr');
    const cell = (value) => noData(item) ? 'No data recorded' : numberFormat.format(count(value)) + (item.complete === false ? ' (partial)' : '');
    row.append(element('th', periodLabel(item, false)), element('td', cell(item.blocked)), element('td', cell(item.allowed)));
    row.firstChild.scope = 'row';
    return row;
  }));
}

/* ---------- Top blocked ---------- */

function renderBreakdown(mode, data) {
  const key = mode === 'full' && range === 'day' ? 'today' : 'week';
  const word = key === 'today' ? 'today' : 'last 7 days';
  $('reason-range').textContent = word;
  $('top-range').textContent = word;
  const categories = data ? list(insights.categories?.[key]) : [];
  const total = categories.reduce((sum, item) => sum + count(item.blocked), 0);
  $('categories').className = 'list counts';
  $('categories').replaceChildren(...categories
    .filter((item) => item.id !== 'other' || count(item.blocked))
    .map((item) => {
      const value = count(item.blocked);
      const li = element('li', null, value ? '' : 'zero');
      const row = element('div', null, 'row');
      const main = element('div', null, 'main');
      main.append(fitted('div', categoryLabels[item.id] || item.id, 'end', 'line1'));
      const trail = element('span', numberFormat.format(value), 'trail');
      if (total && value) trail.append(element('span', percent(value / total), 'share'));
      row.append(main, trail);
      li.append(row);
      return li;
    }));
  const tops = data ? list(insights.top_blocked?.[key]) : [];
  $('top-empty').hidden = Boolean(tops.length);
  $('top-empty-text').textContent = mode === 'none' ? 'History is off, so nothing is counted.' : 'Domains appear here once something is blocked.';
  $('categories').closest('div').hidden = !data;
  $('top-domains').className = 'list tops';
  $('top-domains').replaceChildren(...tops.map((item) => {
    const li = element('li');
    const row = element('button', null, 'row');
    row.type = 'button';
    row.setAttribute('aria-label', item.host + ', ' + plural(count(item.count), 'block', 'blocks') + '. Show in activity');
    const main = element('span', null, 'main');
    main.append(fitted('span', item.host, 'host', 'line1 host'), element('span', categoryWords[item.category] || 'Other', 'line2'));
    row.append(main, element('span', numberFormat.format(count(item.count)), 'trail'));
    row.addEventListener('click', () => focusHost(item.host));
    li.append(row);
    return li;
  }));
  if (!$('panel-top').hidden) fitAll($('panel-top'));
}

/* ---------- Threats ---------- */

function renderThreats(mode, data) {
  const threats = insights?.threats;
  const week = data ? count(threats?.week) : 0;
  const today = data ? count(threats?.today) : 0;
  const tabCount = $('threat-tab-count');
  tabCount.textContent = week ? numberFormat.format(week) : '';
  if (week) tabCount.dataset.state = 'threat'; else delete tabCount.dataset.state;
  $('threats-title').hidden = !week;
  $('threats-title').textContent = today
    ? numberFormat.format(today) + ' stopped today' + (week > today ? ' · ' + numberFormat.format(week) + ' this week' : '')
    : numberFormat.format(week) + ' stopped this week';
  $('threats-empty').hidden = Boolean(week);
  $('threats-empty-title').textContent = mode === 'none' ? 'History is off' : data ? 'No threats this week' : 'No threats yet';
  $('threats-empty-text').textContent = mode === 'none'
    ? 'Threats are still blocked; turn history on to list them here.'
    : 'Malware, phishing and look-alike sites appear here when Egress Guard blocks them.';
  let rows = [];
  if (week && mode === 'full') {
    rows = list(threats.recent).map((item) => [item.host, reasonText(item.source), timeNode(item.at)]);
  } else if (week) {
    rows = list(insights.top_blocked?.week).filter((item) => item.category === 'threats')
      .map((item) => [item.host, 'Threat · ' + plural(count(item.count), 'block', 'blocks'), timeNode(item.last, true)]);
  }
  $('threat-list').replaceChildren(...rows.map(([host, reason, when]) => {
    const li = element('li');
    const row = element('div', null, 'row');
    const main = element('div', null, 'main');
    main.append(fitted('div', host, 'host', 'line1 host'), element('div', reason, 'line2'));
    const trail = element('span', null, 'trail');
    trail.append(when);
    row.append(main, trail);
    li.append(row);
    return li;
  }));
  if (!$('panel-threats').hidden) fitAll($('panel-threats'));
}

/* ---------- Tabs (ARIA tabs pattern, automatic activation) ---------- */

const tabs = [...document.querySelectorAll('[role="tab"]')];

function selectTab(tab, focus) {
  for (const other of tabs) {
    const selected = other === tab;
    other.setAttribute('aria-selected', String(selected));
    other.tabIndex = selected ? 0 : -1;
    $(other.getAttribute('aria-controls')).hidden = !selected;
  }
  if (focus) tab.focus();
  fitAll($(tab.getAttribute('aria-controls')));
}

function focusHost(host) {
  selectTab($('tab-activity'));
  $('hostname').value = host;
  shown = PAGE;
  clearLookup();
  renderActivity();
  $('hostname').scrollIntoView({block: 'center', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth'});
  $('hostname').focus({preventScroll: true});
}

/* ---------- Activity ---------- */

function renderActivity() {
  const search = $('hostname').value.trim().toLowerCase();
  const history = activityMeta.history;
  const filtered = events?.filter((event) => (decisionFilter === 'all' || event.decision === decisionFilter)
    && (!search || event.host?.toLowerCase().includes(search))) || [];
  const notes = [];
  if (events && history === 'aggregate') notes.push('Daily totals per UTC day; allowed traffic is counted without hostnames.');
  if (activityMeta.dropped) notes.push(plural(activityMeta.dropped, 'event was', 'events were') + ' not recorded because the ledger was busy.');
  $('activity-note').textContent = notes.join(' ');
  $('activity-note').hidden = !notes.length;
  $('decisions').hidden = history === 'none' || !events?.length;

  let empty = null;
  if (!events) empty = ['Activity could not be loaded', 'Refresh to try again.'];
  else if (history === 'none') empty = ['History is off', 'Nothing is kept on disk. Enter a domain above to check how it would be handled.'];
  else if (!events.length) empty = ['No activity yet', 'Decisions appear here as apps go online through the proxy.'];
  else if (!filtered.length) empty = ['No matches', search ? 'Press Enter to check how ' + search + ' would be handled.' : 'Nothing recent matches this filter.'];
  $('activity-empty').hidden = !empty;
  if (empty) {
    $('activity-empty-title').textContent = empty[0];
    $('activity-empty-text').textContent = empty[1];
  }
  $('activity-rows').hidden = !filtered.length;
  $('activity-more').hidden = filtered.length <= shown;
  $('activity-rows').replaceChildren(...filtered.slice(0, shown).map(activityRow));
  fitAll($('activity-rows'));
}

function activityRow(event) {
  const row = element('li', null, 'row');
  const category = categoryOf(event.reason);
  const blocked = event.decision === 'blocked';
  const threat = blocked && category === 'threats';
  const label = blocked ? 'Blocked' : event.decision === 'allowed' ? 'Allowed' : (event.decision || '—');
  const reason = reasonText(event.reason) + (event.count > 1 ? ' · ×' + numberFormat.format(event.count) : '');
  const decision = element('span', label, 'dec ' + (blocked ? 'blocked' : 'allowed'));
  // Stopped threats are the one place in the list that carries a state colour.
  if (threat) { decision.dataset.state = 'threat'; decision.classList.add('state-text'); }
  const host = event.host ? fitted('div', event.host, 'host', 'host-c line1 host') : element('div', 'Hostnames not kept', 'host-c line1 nohost');
  const when = element('span', null, 'when');
  const time = timeNode(event.at, event.day_only);
  when.append(time);
  const trail = element('span', null, 'trail');
  trail.append(when);
  const action = rowAction(event, category);
  if (action) {
    const act = element('span', null, 'act');
    act.append(action);
    trail.append(act);
  }
  row.append(decision, host, fitted('div', reason, 'end', 'why line1'), trail);
  row.tabIndex = 0;
  row.setAttribute('aria-label', [label, event.host || 'hostnames not kept', reason, time.textContent].join(', '));
  if (event.host) {
    const check = () => { $('hostname').value = event.host; renderActivity(); void lookup(); };
    row.addEventListener('keydown', (key) => { if (key.key === 'Enter' && key.target === row) { key.preventDefault(); check(); } });
    host.addEventListener('click', check);
  }
  return row;
}

function rowAction(event, category) {
  const c = controls();
  if (!event.host || !writable()) return null;
  let action = null;
  let text = '';
  // Threat blocks are never offered an action.
  if (event.decision === 'blocked' && (category === 'ads' || category === 'cname') && durationOptions(c.allow_minutes).length) {
    action = 'allow'; text = 'Allow…';
  } else if (event.decision === 'blocked' && category === 'manual' && c.unblock === true) {
    action = 'unblock'; text = 'Unblock…';
  } else if (event.decision === 'allowed' && c.block === true) {
    action = 'block'; text = 'Block…';
  }
  if (!action) return null;
  const button = element('button', text, 'btn');
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
    const li = element('li');
    const row = element('div', null, 'row');
    const main = element('div', null, 'main');
    main.append(fitted('div', item.host, 'host', 'line1 host'));
    const expires = formattedDate(item.expires_at, hourFormat);
    const trail = element('span', null, 'trail');
    trail.append(element('span', expires ? 'until ' + expires : '', 'when'));
    if (removable) {
      const act = element('span', null, 'act');
      const remove = element('button', 'Remove…', 'btn');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'Remove temporary allow for ' + item.host);
      remove.addEventListener('click', () => openAction('remove_allow', item.host));
      act.append(remove);
      trail.append(act);
    }
    row.append(main, trail);
    li.append(row);
    return li;
  }));
  fitAll($('temporary-allows'));
}

/* ---------- Domain check ---------- */

function renderLookupActions(container) {
  const c = controls();
  const buttons = [];
  const add = (id, label, action) => {
    const button = element('button', label, 'btn');
    button.type = 'button';
    button.id = id;
    button.addEventListener('click', () => openAction(action, lookupResult?.host));
    buttons.push(button);
  };
  if (lookupResult?.can_allow && lookupResult.decision === 'blocked' && durationOptions(c.allow_minutes).length) add('allow', 'Allow for a while…', 'allow');
  if (lookupResult?.can_block && c.block === true) add('block', 'Block…', 'block');
  if (lookupResult?.can_unblock && c.unblock === true) add('unblock', 'Remove my block…', 'unblock');
  if (!buttons.length) return;
  const group = element('div', null, 'acts');
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
    result.append(element('p', 'Enter a domain such as example.com.', 'inline-error'));
    return;
  }
  const controller = new AbortController();
  lookupController = controller;
  result.append(element('p', 'Checking…', 'muted'));
  try {
    const returned = await api('/api/domain?' + new URLSearchParams({host}), {signal: AbortSignal.any([controller.signal, AbortSignal.timeout(20000)])});
    if (lookupController !== controller) return;
    lookupResult = returned;
    const expires = formattedDate(returned.expires_at);
    const verdict = returned.decision === 'blocked' ? 'Would be blocked' : returned.decision === 'allowed' ? 'Would be allowed' : 'Not decided';
    const name = element('span', returned.host || host, 'host');
    result.replaceChildren(name, element('span', verdict, 'strong'), element('span', reasonText(returned.reason || returned.source), 'muted'));
    if (expires) result.append(element('span', 'temporary allow until ' + expires, 'muted'));
    renderLookupActions(result);
  } catch (error) {
    if (lookupController === controller && error.name !== 'AbortError') result.replaceChildren(element('p', error.message, 'inline-error'));
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
    $('refresh').hidden = false;
    if (snapshot.status === 'fulfilled') {
      status = snapshot.value;
      if ($('notification').dataset.connection) { notice('notification', ''); delete $('notification').dataset.connection; }
    } else {
      status = null;
      notice('notification', snapshot.reason.message, true);
      $('notification').dataset.connection = '1';
    }
    renderHealth();
    renderExceptions(status?.temporary_allows, controls().remove_allow === true);
    insights = summary.status === 'fulfilled' && summary.value && typeof summary.value === 'object' ? summary.value : null;
    renderOutcome();
    if (!$('activity-rows').contains(document.activeElement)) {
      const next = activity.status === 'fulfilled' && activity.value.available !== false && Array.isArray(activity.value.events) ? activity.value.events : null;
      const value = activity.status === 'fulfilled' ? activity.value : {};
      activityMeta = {history: ['aggregate', 'none'].includes(value.history) ? value.history : 'full', dropped: Number.isInteger(value.dropped) && value.dropped > 0 ? value.dropped : 0};
      // Relative times age, so the list re-renders each refresh even when rows are unchanged.
      events = next;
      renderActivity();
    }
    $('updated').textContent = 'Updated ' + hourFormat.format(new Date());
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

// Risky actions keep Cancel as the one filled button; safe or restoring actions fill the confirm button.
const safeActions = new Set(['resume', 'block', 'remove_allow', 'refresh_filters', 'resume_canaries']);

function actionDetails(action, host) {
  const c = status.controls || {};
  switch (action) {
    case 'pause':
      return ['Pause ad filtering?', 'Ads and trackers on proxy connections can load until filtering resumes. Malware and phishing filtering stays on.', 'Pause filtering', durationOptions(c.pause_minutes)];
    case 'resume':
      return ['Resume ad filtering?', 'The proxy applies its ad and tracker filters immediately.', 'Resume filtering'];
    case 'allow':
      return ['Allow ' + host + ' for a while?', host + ' skips the ad and tracker lists until the time runs out. Only this hostname is affected; threat filtering still applies.', 'Allow domain', durationOptions(c.allow_minutes)];
    case 'remove_allow':
      return ['Remove this temporary allow?', 'Normal filter rules apply to ' + host + ' immediately.', 'Remove allow'];
    case 'block':
      return ['Block ' + host + '?', 'The proxy blocks ' + host + ' and its subdomains until you remove the block.', 'Block domain'];
    case 'unblock':
      return ['Remove your block on ' + host + '?', 'The proxy checks ' + host + ' against the remaining rules.', 'Remove block'];
    case 'refresh_filters':
      return ['Update the block lists?', 'The service checks its configured sources for newer lists.', 'Update lists'];
    case 'pause_canaries':
      return ['Pause canary alerts for 15 minutes?', 'Alerts are muted for 15 minutes. The monitor keeps recording events.', 'Pause alerts'];
    case 'resume_canaries':
      return ['Resume canary alerts?', 'The monitor shows notifications for new events immediately.', 'Resume alerts'];
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
      const option = element('option', minutes + ' min');
      option.value = minutes;
      return option;
    }));
  }
  const safe = safeActions.has(action);
  $('confirm-title').textContent = title;
  $('confirm-detail').textContent = detail;
  $('confirm-action').textContent = label;
  $('confirm-action').className = safe ? 'btn primary' : 'btn';
  $('cancel').className = safe ? 'btn' : 'btn primary';
  $('duration-control').hidden = !options;
  notice('notification', '');
  notice('action-status', '');
  $('confirm').showModal();
  (safe ? $('confirm-action') : $('cancel')).focus();
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
  notice('action-status', 'Applying…');

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
    range = value;
    renderOutcome();
  });
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', (event) => {
    const target = {ArrowLeft: index - 1, ArrowRight: index + 1, Home: 0, End: tabs.length - 1}[event.key];
    if (target == null) return;
    event.preventDefault();
    selectTab(tabs[(target + tabs.length) % tabs.length], true);
  });
});
$('activity-more').addEventListener('click', () => { shown += PAGE * 2; renderActivity(); });
$('cancel').addEventListener('click', () => $('confirm').close());
$('confirm').addEventListener('cancel', (event) => {
  if (submitting) event.preventDefault();
});
$('confirm-form').addEventListener('submit', (event) => void submitAction(event));
for (const id of ['pause', 'resume', 'refresh-filters', 'pause-canaries', 'resume-canaries']) {
  $(id).addEventListener('click', () => openAction(id.replaceAll('-', '_')));
}
$('refresh-filters-detail').addEventListener('click', () => openAction('refresh_filters'));
// Truncation is computed for the width each row has now (section 8, rule 5).
let fitFrame = 0;
let lastWidth = 0;
new ResizeObserver(([entry]) => {
  if (Math.round(entry.contentRect.width) === lastWidth) return;
  lastWidth = Math.round(entry.contentRect.width);
  cancelAnimationFrame(fitFrame);
  fitFrame = requestAnimationFrame(() => fitAll());
}).observe($('main'));
document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && document.body.dataset.ready) void refresh();
});

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
