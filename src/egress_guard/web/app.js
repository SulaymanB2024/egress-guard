'use strict';

const $ = (id) => document.getElementById(id);
const timeFormat = new Intl.DateTimeFormat(undefined, {hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'});
const dayFormat = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric'});
const dateFormat = new Intl.DateTimeFormat(undefined, {month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit'});
const numberFormat = new Intl.NumberFormat();
const pageSize = 7;
const stateLabels = {
  active: ['Active', 'good'], admin_required: ['Needs admin', 'warn'], allowed: ['Allowed', 'good'], blocked: ['Blocked', 'bad'],
  degraded: ['Needs attention', 'warn'], disabled: ['Disabled', 'warn'], down: ['Unavailable', 'bad'],
  enabled: ['Enabled', 'good'], failed: ['Failed', 'bad'], fresh: ['Current', 'good'],
  healthy: ['Healthy', 'good'], installed: ['Installed', 'good'], maintenance_blocked: ['Deferred', 'warn'], observed: ['Observed', ''],
  offline: ['Offline', 'bad'], ok: ['OK', 'good'], paused: ['Paused', 'warn'],
  pending: ['Pending', 'warn'], ready: ['Ready', 'good'], restart_required: ['Needs restart', 'warn'], stale: ['Stale', 'warn'],
  unavailable: ['Unavailable', ''], unknown: ['Unknown', ''],
};
const protectionStates = {
  active: ['Filtering active', '✓'], paused: ['Ad filtering paused', 'Ⅱ'],
  degraded: ['Needs attention', '!'], unknown: ['Status unavailable', '·'],
};
const records = new Map();
let status = null;
let events = null;
let eventPage = 0;
let refreshPromise = null;
let lookupController = null;
let lookupResult = null;
let actionRequest = null;
let submitting = false;
let authExpired = false;

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
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

function timeElement(value, formatter, dayOnly) {
  const parsed = date(value);
  if (!parsed) return element('span', '—');
  const sameDay = parsed.toDateString() === new Date().toDateString();
  const time = element('time', dayOnly ? (sameDay ? 'Today' : dayFormat.format(parsed)) : formatter.format(parsed));
  time.dateTime = parsed.toISOString();
  time.title = dayOnly ? dayFormat.format(parsed) : dateFormat.format(parsed);
  if (dayOnly || sameDay) return time;
  const dayAndTime = element('span', null, 'event-time');
  dayAndTime.append(element('span', dayFormat.format(parsed), 'event-day'), time);
  return dayAndTime;
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

function expiredSession() {
  authExpired = true;
  status = null;
  events = null;
  records.clear();
  clearLookup();
  $('activity-rows').replaceChildren();
  for (const id of ['proxies', 'canaries', 'filters', 'maintenance', 'security', 'temporary-allows']) {
    $(id).replaceChildren();
  }
  $('dashboard').hidden = true;
  $('dashboard-nav').hidden = true;
  $('page-footer').hidden = true;
  $('refresh').hidden = true;
  $('confirm').close();
  $('hostname').value = '';
  $('activity-host').value = '';
  $('checked-at').textContent = 'Session needed';
  notice('notification', '');
  notice('connection', 'Open the Egress Guard launcher on this Mac to start a new dashboard session.');
}

async function api(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      credentials: 'same-origin',
      cache: 'no-store',
      signal: options.signal || AbortSignal.timeout(12000),
      ...options,
      headers: {'Accept': 'application/json', 'X-Mac-Guard': '1', ...options.headers},
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

function renderStatus() {
  const protection = status?.protection || {};
  const state = Object.hasOwn(protectionStates, protection.state) ? protection.state : 'unknown';
  const [title, symbol] = protectionStates[state];
  const expires = formattedDate(protection.pause_expires_at);
  $('dashboard').hidden = false;
  $('dashboard-nav').hidden = false;
  $('page-footer').hidden = false;
  $('refresh').hidden = false;
  $('protection-title').textContent = title;
  $('protection-icon').firstElementChild.textContent = symbol;
  $('protection-title').closest('.protection').dataset.state = state;
  const detail = protection.message || 'The service did not report a filtering state.';
  $('protection-detail').textContent = expires ? detail + ' Scheduled to resume ' + expires + '.' : detail;

  const controls = writable() ? status.controls || {} : {};
  $('pause').hidden = state !== 'active' || !durationOptions(controls.pause_minutes).length;
  $('resume').hidden = controls.resume !== true;
  $('refresh-filters').hidden = controls.refresh_filters !== true;
  $('pause-canaries').hidden = controls.pause_canaries !== true;
  $('resume-canaries').hidden = controls.resume_canaries !== true;
  renderLookupActions();

  if (!status) {
    $('exceptions').hidden = true;
    $('security-section').hidden = true;
    for (const id of ['proxies', 'canaries', 'filters', 'maintenance']) renderChecks(id, null);
    return;
  }
  for (const id of ['proxies', 'canaries', 'filters', 'maintenance', 'security']) {
    renderChecks(id, status[id]);
  }
  $('security-section').hidden = !Array.isArray(status.security) || !status.security.length;
  $('exceptions').hidden = !Array.isArray(status.temporary_allows);
  renderExceptions(status.temporary_allows, controls.remove_allow === true);
}

function renderChecks(id, rows) {
  const signature = JSON.stringify(rows ?? null);
  if (records.get(id) === signature) return;
  records.set(id, signature);
  if (!Array.isArray(rows) || !rows.length) {
    $(id).replaceChildren(element('li', 'No status reported.', 'item-detail'));
    return;
  }

  const nodes = rows.map((item) => {
    const row = element('li');
    const details = element('div');
    const entries = Number.isSafeInteger(item.entries) && item.entries >= 0 ? numberFormat.format(item.entries) + ' entries' : '';
    const checked = formattedDate(item.checked_at);
    const published = formattedDate(item.published_at);
    const updated = formattedDate(item.updated_at);
    details.append(element('p', item.name || 'Check', 'item-name'));
    if (item.detail) details.append(element('p', item.detail, 'item-detail'));
    const metadata = [entries, checked && 'Checked ' + checked, published && 'Published ' + published,
      updated && 'Local copy ' + updated].filter(Boolean);
    if (metadata.length) details.append(element('p', metadata.join(' · '), 'item-meta'));
    row.append(details, badge(item.state));
    return row;
  });
  $(id).replaceChildren(...nodes);
}

function renderExceptions(rows, removable) {
  if ($('temporary-allows').contains(document.activeElement)) return;
  const signature = JSON.stringify([rows ?? null, removable]);
  if (records.get('exceptions') === signature) return;
  records.set('exceptions', signature);
  if (!Array.isArray(rows) || !rows.length) {
    $('temporary-allows').replaceChildren(element('li', 'No active exceptions.', 'item-detail'));
    return;
  }

  const nodes = rows.map((item) => {
    const row = element('li');
    const details = element('div');
    const expires = formattedDate(item.expires_at);
    details.append(element('p', item.host, 'host'));
    if (expires) details.append(element('p', 'Expires ' + expires, 'item-detail'));
    row.append(details);
    if (removable) {
      const remove = element('button', 'Remove', 'button quiet');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'Remove temporary allow for ' + item.host);
      remove.addEventListener('click', () => openAction('remove_allow', item.host));
      row.append(remove);
    }
    return row;
  });
  $('temporary-allows').replaceChildren(...nodes);
}

function renderActivity() {
  const search = $('activity-host').value.trim().toLowerCase();
  const decision = $('activity-decision').value;
  const filtered = events?.filter((event) => {
    return (decision === 'all' || event.decision === decision) && (!search || event.host?.toLowerCase().includes(search));
  }) || [];
  $('activity-table').hidden = !filtered.length;
  $('activity-pages').hidden = !filtered.length;
  $('activity-message').hidden = Boolean(filtered.length);
  if (!events) {
    $('activity-summary').textContent = 'Recent decisions could not be loaded.';
    $('activity-message').textContent = 'Refresh to try again.';
    return;
  }
  $('activity-summary').textContent = events.length
    ? 'Showing up to ' + numberFormat.format(events.length) + ' recent proxy records. Hostname blocks are grouped by day.'
    : 'Recent decisions from connections seen by this Mac’s proxy.';
  if (!filtered.length) {
    $('activity-message').textContent = events.length ? 'No recent decisions match these filters.' : 'No recent activity recorded.';
    $('activity-rows').replaceChildren();
    return;
  }

  eventPage = Math.min(eventPage, Math.ceil(filtered.length / pageSize) - 1);
  const start = eventPage * pageSize;
  const end = Math.min(start + pageSize, filtered.length);
  const rows = filtered.slice(start, end).map((event) => {
    const row = element('tr');
    const time = element('td');
    time.append(timeElement(event.at, timeFormat, event.day_only));
    const domain = element('td');
    if (event.host) {
      const button = element('button', event.host, 'host host-button');
      button.type = 'button';
      button.setAttribute('aria-label', 'Check ' + event.host);
      button.addEventListener('click', () => {
        $('hostname').value = event.host;
        $('hostname').focus({preventScroll: true});
        $('domain').scrollIntoView({block: 'nearest'});
        void lookup();
      });
      domain.append(button);
    } else {
      domain.textContent = '—';
    }
    const state = element('td');
    state.append(badge(event.decision));
    row.append(time, domain, state, element('td', event.reason || '—'));
    return row;
  });
  $('activity-rows').replaceChildren(...rows);
  $('activity-range').textContent = (start + 1) + '–' + end + ' of ' + filtered.length;
  $('activity-prev').disabled = !eventPage;
  $('activity-next').disabled = end >= filtered.length;
}

function renderLookupActions() {
  const controls = writable() ? status.controls || {} : {};
  $('allow').hidden = !lookupResult?.can_allow || !durationOptions(controls.allow_minutes).length;
  $('block').hidden = !lookupResult?.can_block || controls.block !== true;
  $('unblock').hidden = !lookupResult?.can_unblock || controls.unblock !== true;
  $('lookup-actions').hidden = $('allow').hidden && $('block').hidden && $('unblock').hidden;
}

function clearLookup() {
  lookupController?.abort();
  lookupController = null;
  lookupResult = null;
  $('lookup-result').hidden = true;
  $('lookup-result').replaceChildren();
  renderLookupActions();
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
    result.replaceChildren(badge(returned.decision), element('span', returned.host || host, 'host'));
    if (returned.reason) result.append(element('p', returned.reason));
    if (expires) result.append(element('p', 'Temporary allow expires ' + expires + '.'));
    renderLookupActions();
  } catch (error) {
    if (lookupController === controller && error.name !== 'AbortError') result.replaceChildren(element('p', error.message, 'error'));
  }
}

async function refresh(manual = false) {
  if (authExpired || submitting) return;
  if (refreshPromise) return refreshPromise;
  if (manual) $('refresh').disabled = true;

  refreshPromise = (async () => {
    const loaded = await Promise.allSettled([api('/api/status'), api('/api/activity')]);
    if (authExpired) return;
    const [snapshot, activity] = loaded;
    if (snapshot.status === 'fulfilled') {
      status = snapshot.value;
      notice('connection', '');
      const checked = formattedDate(status.checked_at, timeFormat);
      $('checked-at').textContent = checked ? 'Checked at ' + checked : 'Status loaded';
    } else {
      status = null;
      $('checked-at').textContent = 'Status unavailable';
      notice('connection', snapshot.reason.message, true);
    }
    renderStatus();
    if (!$('activity-rows').contains(document.activeElement)) {
      const next = activity.status === 'fulfilled' && activity.value.available !== false && Array.isArray(activity.value.events) ? activity.value.events : null;
      const signature = JSON.stringify(next);
      if (records.get('activity') !== signature) {
        records.set('activity', signature);
        events = next;
        renderActivity();
      }
    }
  })();

  try {
    await refreshPromise;
  } finally {
    refreshPromise = null;
    $('refresh').disabled = false;
  }
}

function actionDetails(action, host) {
  const controls = status.controls || {};
  switch (action) {
    case 'pause':
      return ['Pause ad filtering?', 'Ads and trackers on proxy connections can load until filtering resumes. Malware filtering stays active.', 'Pause filtering', durationOptions(controls.pause_minutes)];
    case 'resume':
      return ['Resume ad filtering?', 'The proxy will apply its ad and tracker filters immediately.', 'Resume filtering'];
    case 'allow':
      return ['Allow this domain temporarily?', host + ' will bypass the matching feed rule until the selected time expires. This applies to this hostname only.', 'Allow domain', durationOptions(controls.allow_minutes)];
    case 'remove_allow':
      return ['Remove this temporary allow?', 'Normal filter rules will apply to ' + host + ' immediately.', 'Remove exception'];
    case 'block':
      return ['Block this domain?', 'The proxy will block ' + host + ' and its subdomains until you remove the manual block.', 'Block domain'];
    case 'unblock':
      return ['Remove this manual block?', 'The proxy will evaluate ' + host + ' against the remaining rules.', 'Remove block'];
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

function resetActivity() {
  eventPage = 0;
  renderActivity();
}

$('refresh').addEventListener('click', () => void refresh(true));
$('lookup').addEventListener('submit', (event) => {
  event.preventDefault();
  void lookup();
});
$('hostname').addEventListener('input', clearLookup);
$('activity-host').addEventListener('input', resetActivity);
$('activity-decision').addEventListener('change', resetActivity);
$('activity-prev').addEventListener('click', () => { eventPage -= 1; renderActivity(); });
$('activity-next').addEventListener('click', () => { eventPage += 1; renderActivity(); });
$('cancel').addEventListener('click', () => $('confirm').close());
$('confirm').addEventListener('cancel', (event) => {
  if (submitting) event.preventDefault();
});
$('confirm-form').addEventListener('submit', (event) => void submitAction(event));
for (const id of ['pause', 'resume', 'allow', 'block', 'unblock', 'refresh-filters', 'pause-canaries', 'resume-canaries']) {
  $(id).addEventListener('click', () => {
    const host = ['allow', 'block', 'unblock'].includes(id) ? lookupResult?.host : undefined;
    openAction(id.replaceAll('-', '_'), host);
  });
}

async function initialize() {
  const fragment = window.location.hash.slice(1);
  if (/^[A-Za-z0-9_-]{43}$/.test(fragment)) {
    window.history.replaceState(null, '', window.location.pathname);
    try {
      await api('/api/session', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({token: fragment}),
      });
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
