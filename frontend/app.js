// ============================================
// GuardianAI - Passive Real-Time Agent Monitor
// ============================================

let ws = null;
let blockedCount = 0;
let allowedCount = 0;
let nodeIndex = 0;

// ---- Base path (works behind reverse proxy) ----
const BASE_PATH = location.pathname.replace(/\/$/, '');

// ---- WebSocket Connection ----

function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${location.host}${BASE_PATH}/ws/events`);

    ws.onopen = () => console.log('[Guardian] Connected to event stream');

    ws.onmessage = (e) => {
        const event = JSON.parse(e.data);
        handleEvent(event);
    };

    ws.onclose = () => {
        console.log('[Guardian] Disconnected, reconnecting in 3s...');
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => console.error('[Guardian] WS error:', err);
}

// ---- Event Router ----

function handleEvent(event) {
    switch (event.type) {
        case 'agent_activity':
            renderActivityCard(event);
            break;
        case 'decision':
            renderDecisionCard(event);
            break;
        case 'guardian_summary':
            updateSummaryCard(event);
            break;
        case 'status':
            updateStatus(event);
            break;
    }
}

// ---- Render: Agent Activity (Left Panel) ----
// Generic renderer: adapts to ANY agent system based on data shape, not event names.

function renderActivityCard(event) {
    hideEmpty('activityEmpty');
    const list = document.getElementById('activityList');

    const card = document.createElement('div');
    const data = event.data || {};
    const elapsed = `<span class="elapsed-badge">${event.elapsed.toFixed(1)}s</span>`;
    const taskTag = event.task_id ? `<span class="task-tag">${event.task_id}</span>` : '';
    const label = formatEventType(event.event_type);
    const category = classifyEvent(event);

    card.className = `event-card activity-card activity-${category}`;
    const appSource = data._source || '';
    card.dataset.source = appSource;
    card.dataset.category = category;

    // Hide if filtered by app or category
    const activeFilter = document.getElementById('activityFilter')?.value || '__all';
    if (selectedApp !== '__all' && appSource && appSource !== selectedApp) {
        card.style.display = 'none';
    } else if (activeFilter !== '__all' && category !== activeFilter) {
        card.style.display = 'none';
    }

    // Hide if filtered
    if (selectedApp !== '__all' && appSource && appSource !== selectedApp) {
        card.style.display = 'none';
    }

    const source = appSource ? `<span class="source-badge" style="background:${sourceColor(appSource)}">${escapeHtml(appSource)}</span>` : '';

    let body = '';

    switch (category) {
        case 'query': {
            const queryText = data.query || data.prompt || data.input || event.summary;
            card.className = 'event-card query-card';
            body = `
                <div class="card-header">${iconSvg('search')}<span class="card-title">${label}</span>${source}${elapsed}</div>
                <div class="query-text">${escapeHtml(queryText)}</div>`;
            break;
        }

        case 'agent': {
            const agentName = (event.agent || data.agent || data.name || 'agent').toUpperCase();
            card.className = `event-card agent-start-card`;
            card.style.borderLeftColor = agentColor(agentName);
            body = `
                <div class="agent-start-row">
                    ${iconSvg('zap')}<span class="agent-name" style="color:${agentColor(agentName)}">${agentName}</span>${source}${taskTag}${elapsed}
                </div>`;
            break;
        }

        case 'score': {
            const score = data.score ?? data.coherence_score ?? data.quality_score ?? '?';
            const passed = data.passed ?? data.valid ?? (typeof score === 'number' ? score >= 7 : null);
            const scoreClass = typeof score === 'number' ? (score >= 7 ? 'score-good' : score >= 4 ? 'score-mid' : 'score-bad') : '';
            const passHtml = passed !== null ? `<span class="eval-pass ${passed ? 'pass-yes' : 'pass-no'}">${passed ? '&#10003; PASS' : '&#10007; FAIL'}</span>` : '';
            const strengths = (data.strengths || []).slice(0, 2);
            const weaknesses = (data.weaknesses || []).slice(0, 2);
            const tags = (data.do_services_found || data.services_found || data.tags || []).slice(0, 6);
            body = `
                <div class="card-header">${iconSvg('bar-chart')}<span class="card-title">${label}</span>${source}${taskTag}${elapsed}</div>
                <div class="eval-row">
                    <span class="eval-score ${scoreClass}">${score}${typeof score === 'number' ? '/10' : ''}</span>
                    ${passHtml}
                </div>
                ${strengths.length ? `<div class="eval-list eval-strengths">${strengths.map(s => '<span>+ ' + escapeHtml(String(s).substring(0, 80)) + '</span>').join('')}</div>` : ''}
                ${weaknesses.length ? `<div class="eval-list eval-weaknesses">${weaknesses.map(w => '<span>- ' + escapeHtml(String(w).substring(0, 80)) + '</span>').join('')}</div>` : ''}
                ${tags.length ? `<div class="service-tags">${tags.map(t => '<span class="service-tag">' + escapeHtml(t) + '</span>').join('')}</div>` : ''}`;
            break;
        }

        case 'status': {
            // Status/progress message (e.g., "Researching Salesforce...")
            const msg = data.message || event.summary || label;
            card.className = 'event-card activity-card activity-status';
            body = `
                <div class="card-header">${iconSvg('activity')}<span class="card-title">${escapeHtml(msg)}</span>${source}${elapsed}</div>`;
            break;
        }

        case 'output': {
            const text = data.content || data.output || data.specification || data.result || data.response || data.raw || '';
            const preview = String(text).substring(0, 180);
            const chips = extractChips(data);
            body = `
                <div class="card-header">${iconSvg('layers')}<span class="card-title">${label}</span>${source}${chips.length ? chips.map(c => `<span class="meta-chip">${escapeHtml(c)}</span>`).join('') : ''}${elapsed}</div>
                ${preview ? `<div class="card-detail">${escapeHtml(preview)}${text.length > 180 ? '...' : ''}</div>` : ''}`;
            break;
        }

        case 'data': {
            // Event with structured metadata (docs fetched, counts, etc.)
            const chips = extractChips(data);
            body = `
                <div class="card-header">${iconSvg('database')}<span class="card-title">${label}</span>${elapsed}</div>
                ${chips.length ? `<div class="card-meta">${chips.map(c => `<span class="meta-chip">${escapeHtml(c)}</span>`).join('')}</div>` : ''}
                ${event.summary ? `<div class="card-detail">${escapeHtml(event.summary)}</div>` : ''}`;
            break;
        }

        case 'complete': {
            card.className = 'event-card complete-card';
            body = `<div class="complete-row">${iconSvg('check-circle')}<span class="card-title">Complete</span>${elapsed}</div>`;
            break;
        }

        case 'error': {
            card.className = 'event-card error-card';
            body = `
                <div class="card-header">${iconSvg('x-circle')}<span class="card-title">Error</span>${elapsed}</div>
                <div class="card-detail">${escapeHtml(data.message || data.error || event.summary)}</div>`;
            break;
        }

        default: {
            body = `
                <div class="card-header">${iconSvg('activity')}<span class="card-title">${label}</span>${elapsed}</div>
                <div class="card-detail">${escapeHtml(event.summary)}</div>`;
        }
    }

    card.innerHTML = body;
    list.appendChild(card);
    scrollToBottom(list);
}

// Classify any event into a rendering category based on its data shape
function classifyEvent(event) {
    const type = event.event_type || '';
    const data = event.data || {};

    if (type.includes('error') || type === 'error') return 'error';
    if (type === 'complete' || type === 'done' || type === 'finished') return 'complete';
    if (data.query || data.prompt || data.input || type.includes('query') || type.includes('request')) return 'query';
    if (type.includes('start') && (event.agent || data.agent || data.name)) return 'agent';
    if ('score' in data || 'coherence_score' in data || 'quality_score' in data || data.passed !== undefined || data.valid !== undefined) return 'score';
    if (data.content || data.output || data.specification || data.result || data.response || data.raw) return 'output';
    if (data.message || type === 'status') return 'status';
    return 'data';
}

// Extract human-readable chips from event data (counts, iterations, etc.)
function extractChips(data) {
    const chips = [];
    const chipKeys = {
        'iteration': v => `iter ${v}`,
        'criteria_count': v => `${v} criteria`,
        'services': v => typeof v === 'number' ? `${v} services` : null,
        'service_count': v => `${v} services`,
        'chars': v => `${(v / 1000).toFixed(1)}K chars`,
        'complexity': v => String(v).toUpperCase(),
        'iterations': v => `${v} iterations`,
        'subtasks': v => Array.isArray(v) ? `${v.length} subtasks` : null,
    };
    for (const [key, fmt] of Object.entries(chipKeys)) {
        if (key in data && data[key] !== null && data[key] !== undefined) {
            const label = fmt(data[key]);
            if (label) chips.push(label);
        }
    }
    return chips;
}

// Consistent color for agent names
function agentColor(name) {
    const colors = ['#f59e0b', '#3b82f6', '#22c55e', '#a855f7', '#06b6d4', '#ef4444', '#ec4899', '#eab308'];
    let hash = 0;
    for (let i = 0; i < name.length; i++) hash = name.charCodeAt(i) + ((hash << 5) - hash);
    return colors[Math.abs(hash) % colors.length];
}

// Simple SVG icon helper
function iconSvg(name) {
    const icons = {
        'search': '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
        'zap': '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
        'bar-chart': '<path d="M12 20V10"/><path d="M18 20V4"/><path d="M6 20v-4"/>',
        'layers': '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
        'database': '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
        'activity': '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
        'check-circle': '<path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
        'x-circle': '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
    };
    const path = icons[name] || icons['activity'];
    return `<svg class="card-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${path}</svg>`;
}

function getEventBadgeClass(eventType) {
    const map = {
        'query_received': 'query',
        'decomposition_start': 'decomposition',
        'decomposition_result': 'decomposition',
        'wave_start': 'wave',
        'subtask_start': 'status-event',
        'agent_start': 'status-event',
        'docs_fetched': 'docs',
        'planner_output': 'planner',
        'generator_output': 'generator',
        'evaluation': 'evaluation',
        'subtask_complete': 'status-event',
        'synthesis_start': 'synthesis',
        'synthesis_complete': 'synthesis',
        'validation_result': 'validation',
        'complete': 'status-event',
        'error': 'status-event',
    };
    return map[eventType] || 'status-event';
}

function formatEventType(eventType) {
    return eventType.replace(/_/g, ' ');
}

// ---- Render: Guardian Decisions (Right Panel) ----

function renderDecisionCard(event) {
    hideEmpty('decisionEmpty');
    const list = document.getElementById('decisionList');

    const isBlocked = event.action === 'blocked';
    const card = document.createElement('div');
    card.className = `event-card decision-card ${isBlocked ? 'blocked' : 'allowed'}`;
    card.dataset.source = event.details?._source || '';
    card.dataset.action = event.action || '';
    card.dataset.threat = event.threat_level || 'none';

    // Hide if filtered
    const decFilter = document.getElementById('decisionFilter')?.value || '__all';
    if (!matchesDecisionFilter(card, decFilter)) {
        card.style.display = 'none';
    }

    // Hide if filtered by app
    if (selectedApp !== '__all' && card.dataset.source && card.dataset.source !== selectedApp) {
        card.style.display = 'none';
    }

    const decisionIcon = isBlocked
        ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
        : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';

    const iconClass = isBlocked ? 'blocked-icon' : 'allowed-icon';
    const actionClass = isBlocked ? 'blocked-text' : 'allowed-text';

    // Threat level badge
    let threatHtml = '';
    if (event.threat_level && event.threat_level !== 'none') {
        threatHtml = `<span class="threat-level ${event.threat_level}">${event.threat_level.toUpperCase()}</span>`;
    } else if (!isBlocked) {
        threatHtml = '<span class="threat-level none">SAFE</span>';
    }

    // OWASP badge
    let owaspHtml = '';
    if (event.owasp_id) {
        owaspHtml = `<span class="owasp-badge" title="${escapeHtml(event.owasp_label || '')}">${escapeHtml(event.owasp_id)}</span>`;
    }

    // Rule name
    let ruleHtml = '';
    if (event.rule_name) {
        ruleHtml = `<div class="decision-rule">Rule: ${escapeHtml(event.rule_name)}</div>`;
    }

    // Reason
    let reasonHtml = '';
    if (event.reason) {
        reasonHtml = `<div class="decision-reason">${escapeHtml(event.reason)}</div>`;
    }

    // Source app badge
    const srcName = event.details?._source || '';
    const srcHtml = srcName ? `<span class="source-badge" style="background:${sourceColor(srcName)}">${escapeHtml(srcName)}</span>` : '';

    const eventLabel = formatEventType(event.event_type);
    const agentLabel = event.agent ? ` (${event.agent})` : '';

    // Details (exclude _source from display)
    let detailsHtml = '';
    if (event.details && Object.keys(event.details).length > 0) {
        const filtered = Object.fromEntries(Object.entries(event.details).filter(([k]) => k !== '_source'));
        if (Object.keys(filtered).length > 0) {
            detailsHtml = `<div class="decision-args">${escapeHtml(JSON.stringify(filtered, null, 2))}</div>`;
        }
    }

    // Build expandable detail panel for blocked cards
    let expandHtml = '';
    if (isBlocked) {
        const owaspInfo = getOwaspInfo(event.owasp_id);
        const remediation = getRemediation(event.rule_name);

        expandHtml = `
        <div class="decision-expand" style="display:none">
            <div class="expand-section">
                <div class="expand-label">What happened</div>
                <div class="expand-text">${escapeHtml(event.reason || '')}</div>
            </div>
            ${owaspInfo ? `
            <div class="expand-section">
                <div class="expand-label">OWASP ${escapeHtml(event.owasp_id)}: ${escapeHtml(event.owasp_label || '')}</div>
                <div class="expand-text">${owaspInfo}</div>
            </div>` : ''}
            <div class="expand-section">
                <div class="expand-label">How to fix</div>
                <div class="expand-text">${remediation}</div>
            </div>
            ${detailsHtml ? `
            <div class="expand-section">
                <div class="expand-label">Event data</div>
                ${detailsHtml}
            </div>` : ''}
        </div>`;
    }

    card.innerHTML = `
        <div class="decision-header ${isBlocked ? 'clickable' : ''}" ${isBlocked ? 'onclick="toggleExpand(this)"' : ''}>
            <div class="decision-icon ${iconClass}">${decisionIcon}</div>
            <span class="decision-action ${actionClass}">${event.action.toUpperCase()}</span>
            ${srcHtml}
            <span class="decision-tool">${eventLabel}${agentLabel}</span>
            ${isBlocked ? '<span class="expand-arrow">&#9662;</span>' : ''}
        </div>
        <div class="decision-badges">
            ${threatHtml}${owaspHtml}
        </div>
        ${reasonHtml}
        ${ruleHtml}
        ${expandHtml}
    `;

    list.appendChild(card);
    scrollToBottom(list);

    addTimelineNode(isBlocked);
}

// ---- Status Updates ----

function updateStatus(event) {
    const badge = document.getElementById('statusBadge');
    const text = badge.querySelector('.status-text');

    badge.className = 'status-badge';

    switch (event.status) {
        case 'connected':
        case 'observing':
            badge.classList.add('running');
            text.textContent = 'OBSERVING';
            break;
        case 'disconnected':
            badge.className = 'status-badge';
            text.textContent = 'RECONNECTING';
            break;
        case 'completed':
            badge.classList.add('completed');
            text.textContent = 'COMPLETE';
            break;
        case 'error':
            badge.className = 'status-badge';
            text.textContent = 'ERROR';
            break;
    }
}

// ---- Timeline ----

function addTimelineNode(isBlocked) {
    const timeline = document.getElementById('timeline');
    const node = document.createElement('div');
    node.className = `timeline-node ${isBlocked ? 'blocked' : 'allowed'}`;

    nodeIndex++;
    const timelineHeight = timeline.offsetHeight;
    const padding = 40;
    const spacing = 28;
    const top = padding + ((nodeIndex - 1) * spacing) % (timelineHeight - padding * 2);

    node.style.top = `${top}px`;
    timeline.appendChild(node);
}

// ---- Helpers ----

function updateCounter(id, value) {
    const el = document.getElementById(id);
    const num = el.querySelector('.counter-num');
    num.textContent = value;
    num.style.transform = 'scale(1.3)';
    setTimeout(() => { num.style.transform = 'scale(1)'; }, 200);
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function scrollToBottom(el) {
    requestAnimationFrame(() => {
        el.scrollTop = el.scrollHeight;
    });
}

function hideEmpty(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
}

// ---- Spin animation ----
const style = document.createElement('style');
style.textContent = `
    @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    .spin { animation: spin 1s linear infinite; }
    .counter-num { transition: transform 0.2s ease; }
`;
document.head.appendChild(style);

// ---- Source colors for multi-target ----

const _sourceColors = {};
const _palette = ['#06b6d4', '#a855f7', '#f59e0b', '#22c55e', '#ec4899', '#3b82f6'];
let _colorIdx = 0;
let selectedApp = '__all';

function sourceColor(name) {
    if (!_sourceColors[name]) {
        _sourceColors[name] = _palette[_colorIdx % _palette.length];
        _colorIdx++;
    }
    return _sourceColors[name];
}

// ---- App selector ----

function onAppSelect() {
    selectedApp = document.getElementById('appSelect').value;
    const catFilter = document.getElementById('activityFilter')?.value || '__all';

    // Filter activity cards by app + category
    document.querySelectorAll('#activityList .event-card').forEach(card => {
        const src = card.dataset.source || '';
        const cat = card.dataset.category || '';
        const appMatch = selectedApp === '__all' || !src || src === selectedApp;
        const catMatch = catFilter === '__all' || cat === catFilter;
        card.style.display = (appMatch && catMatch) ? '' : 'none';
    });

    // Filter decision cards by app + decision filter
    const decFilter = document.getElementById('decisionFilter')?.value || '__all';
    document.querySelectorAll('#decisionList .event-card:not(.summary-card)').forEach(card => {
        const src = card.dataset.source || '';
        const appMatch = selectedApp === '__all' || !src || src === selectedApp;
        card.style.display = (appMatch && matchesDecisionFilter(card, decFilter)) ? '' : 'none';
    });

    // Re-render summary with selected app's stats
    renderSummary();
}

// ---- App Management ----

async function loadTargets() {
    try {
        const resp = await fetch(`${BASE_PATH}/api/targets`);
        const data = await resp.json();
        const targets = data.targets || [];
        updateAppSelect(targets);
        updateAppsList(targets);
    } catch (e) {
        console.error('Failed to load targets:', e);
    }
}

function updateAppSelect(targets) {
    const select = document.getElementById('appSelect');
    const current = select.value;
    select.innerHTML = '<option value="__all">All Apps</option>';
    targets.forEach(t => {
        const opt = document.createElement('option');
        opt.value = t.name;
        opt.textContent = `${t.name} ${t.status === 'connected' ? '' : '(offline)'}`;
        select.appendChild(opt);
    });
    select.value = current || '__all';
}

function updateAppsList(targets) {
    const list = document.getElementById('appsList');
    if (!targets.length) {
        list.innerHTML = '<p class="empty-hint">No apps connected yet</p>';
        return;
    }
    list.innerHTML = targets.map(t => `
        <div class="app-item">
            <span class="app-status-dot ${t.status}"></span>
            <span class="app-item-name">${escapeHtml(t.name)}</span>
            <span class="app-item-url">${escapeHtml(t.ws_url)}</span>
            <button class="app-remove-btn" onclick="removeApp('${escapeHtml(t.name)}')" title="Disconnect">&times;</button>
        </div>
    `).join('');
}

function openAddModal() {
    document.getElementById('addModal').style.display = 'flex';
    document.getElementById('connectStatus').textContent = '';
    loadTargets();
}

function closeAddModal(e) {
    if (e && e.target !== e.currentTarget) return;
    document.getElementById('addModal').style.display = 'none';
}

function buildObserverUrl(appUrl) {
    // Strip trailing slash
    let base = appUrl.replace(/\/+$/, '');
    // Convert http(s) to ws(s)
    base = base.replace(/^https:\/\//, 'wss://').replace(/^http:\/\//, 'ws://');
    // If no protocol, assume wss
    if (!base.startsWith('ws')) base = 'wss://' + base;
    return base + '/ws-observe';
}

async function connectApp() {
    const name = document.getElementById('appName').value.trim();
    const rawUrl = document.getElementById('appUrl').value.trim();
    const statusEl = document.getElementById('connectStatus');
    const btn = document.getElementById('connectBtn');

    if (!name || !rawUrl) {
        statusEl.innerHTML = renderVerifyError({ message: 'Please fill in both fields', code: 'missing_fields' });
        statusEl.className = 'connect-status error';
        return;
    }

    const wsUrl = buildObserverUrl(rawUrl);
    btn.disabled = true;

    // Step 1: Verify the app
    statusEl.innerHTML = '<div class="verify-steps"><div class="verify-step active">Checking if app is reachable...</div></div>';
    statusEl.className = 'connect-status';

    try {
        const verifyResp = await fetch(`${BASE_PATH}/api/targets/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ws_url: wsUrl }),
        });
        const verifyData = await verifyResp.json();

        if (verifyData.status !== 'ok') {
            statusEl.innerHTML = renderVerifyError(verifyData);
            statusEl.className = 'connect-status error';
            btn.disabled = false;
            return;
        }

        // Step 2: All checks passed, register
        const fw = verifyData.details?.framework || 'unknown';
        const ver = verifyData.details?.version || '?';
        statusEl.innerHTML = `<div class="verify-steps">
            <div class="verify-step done">App reachable</div>
            <div class="verify-step done">guardian-tap detected (${escapeHtml(fw)} v${escapeHtml(ver)})</div>
            <div class="verify-step done">WebSocket connection verified</div>
            <div class="verify-step active">Registering...</div>
        </div>`;

        const resp = await fetch(`${BASE_PATH}/api/targets`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, ws_url: wsUrl }),
        });
        const data = await resp.json();

        if (resp.ok) {
            statusEl.innerHTML = `<div class="verify-steps">
                <div class="verify-step done">App reachable</div>
                <div class="verify-step done">guardian-tap detected (${escapeHtml(fw)} v${escapeHtml(ver)})</div>
                <div class="verify-step done">WebSocket connection verified</div>
                <div class="verify-step done">Connected to ${escapeHtml(name)}!</div>
            </div>`;
            statusEl.className = 'connect-status success';
            document.getElementById('appName').value = '';
            document.getElementById('appUrl').value = '';
            loadTargets();
        } else {
            statusEl.innerHTML = renderVerifyError({ message: data.error || 'Failed to register', code: 'register_failed' });
            statusEl.className = 'connect-status error';
        }
    } catch (e) {
        statusEl.innerHTML = renderVerifyError({ message: `Network error: ${e.message}`, code: 'connection_error' });
        statusEl.className = 'connect-status error';
    }
    btn.disabled = false;
}

function renderVerifyError(data) {
    const fixes = {
        'app_unreachable': 'Check that the URL is correct and your app is deployed and running.',
        'app_timeout': 'Your app may still be starting up. Wait a minute and try again.',
        'guardian_tap_not_installed': 'Follow Steps 1 and 2 above to install guardian-tap in your app, then redeploy.',
        'no_websocket_support': 'Add <code>websockets</code> to your requirements.txt and redeploy. This is needed for the observer endpoint.',
        'websocket_failed': 'Your hosting platform may not support WebSocket connections. Check proxy/firewall settings (e.g., Cloudflare, nginx).',
        'unexpected_status': 'Check your app logs for errors. There may be a route conflict at /ws-observe.',
        'invalid_response': 'The /ws-observe path exists but is not guardian-tap. Check if another route is using this path.',
        'not_guardian_tap': 'Another route in your app is handling /ws-observe. Remove it, or use a custom path.',
        'connection_error': 'Check the URL and your network connection.',
        'missing_fields': 'Enter both an app name and URL.',
        'register_failed': 'The app was verified but registration failed. Try again.',
    };

    const fix = fixes[data.code] || 'Check the URL and try again.';

    return `
        <div class="verify-error">
            <div class="verify-error-msg">${escapeHtml(data.message)}</div>
            <div class="verify-fix"><strong>How to fix:</strong> ${fix}</div>
        </div>
    `;
}

async function removeApp(name) {
    try {
        await fetch(`${BASE_PATH}/api/targets/${encodeURIComponent(name)}`, { method: 'DELETE' });
        loadTargets();
    } catch (e) {
        console.error('Failed to remove app:', e);
    }
}

// Periodically refresh target statuses
setInterval(loadTargets, 10000);

// ---- Guardian Summary Card ----

// Store latest summary for re-rendering on filter change
let _lastSummary = null;

function updateSummaryCard(event) {
    _lastSummary = event;
    renderSummary();
}

function renderSummary() {
    if (!_lastSummary) return;
    const event = _lastSummary;

    hideEmpty('decisionEmpty');
    const list = document.getElementById('decisionList');

    let card = document.getElementById('summaryCard');
    if (!card) {
        card = document.createElement('div');
        card.id = 'summaryCard';
        card.className = 'event-card summary-card';
        list.insertBefore(card, list.firstChild);
    }

    // Use per-app stats if an app is selected, otherwise global
    let checked, blocked, allowed, byRule, bySeverity;
    if (selectedApp !== '__all' && event.per_app && event.per_app[selectedApp]) {
        const appStats = event.per_app[selectedApp];
        checked = appStats.checked || 0;
        blocked = appStats.blocked || 0;
        allowed = appStats.allowed || 0;
        byRule = appStats.by_rule || {};
        bySeverity = appStats.by_severity || {};
    } else {
        checked = event.total_checked || 0;
        blocked = event.total_blocked || 0;
        allowed = event.total_allowed || 0;
        byRule = event.by_rule || {};
        bySeverity = event.by_severity || {};
    }

    const ruleChips = Object.entries(byRule).map(([rule, count]) =>
        `<span class="summary-chip summary-chip-blocked">${escapeHtml(rule)}: ${count}</span>`
    ).join('');

    const sevChips = Object.entries(bySeverity).map(([sev, count]) =>
        `<span class="summary-chip severity-${sev}">${sev.toUpperCase()}: ${count}</span>`
    ).join('');

    const statusClass = blocked > 0 ? 'summary-warning' : 'summary-clean';
    const statusIcon = blocked > 0
        ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>'
        : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>';

    const appLabel = selectedApp !== '__all' ? ` (${escapeHtml(selectedApp)})` : '';

    card.innerHTML = `
        <div class="summary-header ${statusClass}">
            ${statusIcon}
            <span class="summary-title">${checked} events scanned${appLabel}</span>
        </div>
        <div class="summary-stats">
            <span class="summary-stat summary-allowed">${allowed} safe</span>
            <span class="summary-stat summary-blocked-count">${blocked} blocked</span>
        </div>
        ${sevChips || ruleChips ? `<div class="summary-chips">${sevChips}${ruleChips}</div>` : ''}
    `;

    // Update header counters
    updateCounter('blockedCounter', blocked);
    updateCounter('allowedCounter', allowed);
}

// ---- Decision filter ----

function filterDecisions() {
    const filter = document.getElementById('decisionFilter').value;
    document.querySelectorAll('#decisionList .event-card').forEach(card => {
        const srcMatch = selectedApp === '__all' || !card.dataset.source || card.dataset.source === selectedApp;
        card.style.display = (srcMatch && matchesDecisionFilter(card, filter)) ? '' : 'none';
    });
}

function matchesDecisionFilter(card, filter) {
    if (filter === '__all') return true;
    if (filter === 'blocked') return card.dataset.action === 'blocked';
    if (filter === 'allowed') return card.dataset.action === 'allowed';
    // critical, high, medium
    return card.dataset.threat === filter;
}

// ---- Blocked card expand/collapse ----

function toggleExpand(headerEl) {
    const card = headerEl.closest('.decision-card');
    const panel = card.querySelector('.decision-expand');
    const arrow = headerEl.querySelector('.expand-arrow');
    if (!panel) return;

    const isOpen = panel.style.display !== 'none';
    panel.style.display = isOpen ? 'none' : 'block';
    if (arrow) arrow.textContent = isOpen ? '\u25BE' : '\u25B4';
}

function getOwaspInfo(id) {
    const info = {
        'LLM01': 'An attacker manipulates the LLM through crafted inputs, causing it to execute unintended actions. This can bypass safety measures, produce harmful outputs, or leak sensitive information.',
        'LLM02': 'When an LLM generates output that is not properly validated or sanitized before being passed to downstream systems. This can lead to XSS, SQL injection, or command injection in connected components.',
        'LLM05': 'Vulnerabilities in the supply chain of LLM components (training data, models, plugins) that can be exploited to manipulate model behavior or introduce backdoors.',
        'LLM06': 'The LLM may reveal confidential information, proprietary algorithms, API keys, or other sensitive data through its responses. This can happen when sensitive data appears in training data or user prompts.',
        'LLM07': 'An LLM-based system is granted excessive capabilities (file access, code execution, API calls) beyond what is needed, and an attacker exploits this to perform unauthorized actions.',
    };
    return info[id] || '';
}

function getRemediation(ruleName) {
    const fixes = {
        'prompt_injection': 'Sanitize user inputs before passing to the LLM. Use input validation, system prompt hardening, and output filtering. Consider using a separate LLM call to detect injection attempts before processing.',
        'sensitive_data_leak': 'Never include real credentials, API keys, or tokens in LLM prompts. Use placeholder values in examples. Add output scanning to redact patterns like sk-*, AKIA*, private keys before returning responses to users.',
        'data_exfiltration': 'Block or allowlist outbound URLs that the agent can access. Never allow agents to send data to arbitrary external endpoints. Use egress filtering and monitor outbound connections.',
        'ssrf': 'Validate and sanitize all URLs before making requests. Block access to internal/private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x, localhost). Use URL allowlists for permitted external services.',
        'dangerous_code': 'Run agent-generated code in sandboxed environments with restricted permissions. Never execute code with elevated privileges. Disable dangerous functions (eval, exec, os.system) in the execution environment.',
        'injection': 'Use parameterized queries for database access. Sanitize all LLM outputs before rendering in HTML or passing to command interpreters. Apply Content Security Policy headers.',
        'excessive_agency': 'Follow the principle of least privilege. Only grant agents the minimum permissions needed for their task. Require human approval for high-impact actions (deployments, deletions, infrastructure changes).',
        'eval_manipulation': 'Monitor evaluation scores for anomalies. Validate that agent outputs meet quality thresholds. Use independent evaluation (separate LLM or rule-based checks) to verify results.',
    };
    return fixes[ruleName] || 'Review the flagged content and ensure your agent follows security best practices.';
}

// ---- Activity filter ----

function filterActivity() {
    const filter = document.getElementById('activityFilter').value;
    document.querySelectorAll('#activityList .event-card').forEach(card => {
        const cat = card.dataset.category || '';
        const src = card.dataset.source || '';
        const appMatch = selectedApp === '__all' || !src || src === selectedApp;
        const catMatch = filter === '__all' || cat === filter;
        card.style.display = (appMatch && catMatch) ? '' : 'none';
    });
}

// ---- Stack switcher in modal ----

function switchStack(stack) {
    // Toggle tab active state
    document.querySelectorAll('.stack-tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.stack-tab[onclick="switchStack('${stack}')"]`).classList.add('active');

    // Toggle content visibility
    document.getElementById('stack-python').style.display = stack === 'python' ? '' : 'none';
    document.getElementById('stack-node').style.display = stack === 'node' ? '' : 'none';
    document.getElementById('code-python').style.display = stack === 'python' ? '' : 'none';
    document.getElementById('code-node').style.display = stack === 'node' ? '' : 'none';
}

// ---- Init ----
connectWebSocket();
loadTargets();
