// ============================================
// GuardianAI - Passive Real-Time Agent Monitor
// ============================================

let ws = null;
let flaggedCount = 0;
let allowedCount = 0;
let nodeIndex = 0;

// ---- Base path + session ----
const BASE_PATH = location.pathname.replace(/\/$/, '');

function getSessionId() {
    let sid = localStorage.getItem('guardian_session_id');
    if (!sid) {
        sid = 'gs_' + crypto.randomUUID();
        localStorage.setItem('guardian_session_id', sid);
    }
    return sid;
}
// ?session=app:<name>&token=<key> watches the session of an API-key caller.
// The token is an approver key (or that app's key); it is kept for this tab only.
const URL_PARAMS = new URLSearchParams(location.search);
if (URL_PARAMS.get('token')) {
    sessionStorage.setItem('guardian_token', URL_PARAMS.get('token'));
    // Do not leave the key in the address bar or history.
    URL_PARAMS.delete('token');
    history.replaceState(null, '', location.pathname + (URL_PARAMS.toString() ? '?' + URL_PARAMS : ''));
}
const AUTH_TOKEN = sessionStorage.getItem('guardian_token') || '';
const SESSION_ID = URL_PARAMS.get('session') || getSessionId();
const IS_APP_SESSION = SESSION_ID.startsWith('app:');

function apiHeaders() {
    const h = { 'Content-Type': 'application/json' };
    // app:* sessions are chosen by the API key, never by the header.
    if (!IS_APP_SESSION) h['X-Session-Id'] = SESSION_ID;
    if (AUTH_TOKEN) h['Authorization'] = `Bearer ${AUTH_TOKEN}`;
    return h;
}

// ---- OWASP taxonomy (served by /api/taxonomy, never hard-coded here) ----

let TAXONOMY = { owasp_llm: { items: {} }, owasp_agentic: { items: {} }, rules: {} };

async function loadTaxonomy() {
    try {
        const resp = await fetch(`${BASE_PATH}/api/taxonomy`);
        TAXONOMY = await resp.json();
        renderRuleChips();
    } catch (e) {
        console.error('Failed to load taxonomy:', e);
    }
}

function renderRuleChips() {
    const wrap = document.getElementById('ruleChips');
    if (!wrap) return;
    const rules = Object.entries(TAXONOMY.rules || {}).filter(([, r]) => r.owasp_llm || r.owasp_agentic);
    const seen = new Set();
    const chips = [];
    rules.forEach(([, r]) => {
        const key = r.owasp_llm;
        if (!key || seen.has(key)) return;
        seen.add(key);
        const label = TAXONOMY.owasp_llm.items[key]?.label || '';
        chips.push(`<span class="empty-rule-chip">${escapeHtml(key)} ${escapeHtml(label)}</span>`);
    });
    wrap.innerHTML = chips.join('');
    const hint = document.getElementById('ruleHint');
    if (hint) {
        const agentic = new Set(rules.map(([, r]) => r.owasp_agentic).filter(Boolean));
        hint.textContent = `${rules.length} detectors mapped to ${seen.size} OWASP LLM 2025 and ${agentic.size} Agentic 2026 categories`;
    }
}

// ---- WebSocket Connection ----

function connectWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const q = new URLSearchParams({ session: SESSION_ID });
    if (AUTH_TOKEN) q.set('token', AUTH_TOKEN);
    ws = new WebSocket(`${protocol}//${location.host}${BASE_PATH}/ws/events?${q}`);

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
        case 'approval':
            renderApproval(event);
            break;
    }
}

// ---- Approvals lane ----
// One card per approval. Pending cards have Approve / Deny; resolved cards
// keep their outcome so the history stays visible.

function approvalStatusLabel(a) {
    if (a.status === 'pending') return 'WAITING';
    if (a.status === 'approved') return a.uses > 0 ? `APPROVED, USED ${a.uses}x` : 'APPROVED';
    if (a.reason === 'timeout') return 'DENIED (TIMEOUT)';
    return 'DENIED';
}

function fmtValue(v) {
    return typeof v === 'string' ? v : JSON.stringify(v);
}

function renderApproval(a) {
    // ApprovalEvent (from the socket) and /api/approvals items differ only in field names.
    a = { ...a, tool_name: a.tool_name || a.tool, policy_rule_id: a.policy_rule_id || a.rule_id };
    const lane = document.getElementById('approvalsLane');
    const list = document.getElementById('approvalList');
    if (!lane || !list) return;
    lane.hidden = false;

    let card = list.querySelector(`[data-approval-id="${CSS.escape(a.approval_id)}"]`);
    if (!card) {
        card = document.createElement('div');
        card.className = 'approval-card';
        card.dataset.approvalId = a.approval_id;
        list.prepend(card);
    }
    card.dataset.status = a.status;

    const args = Object.entries(a.arguments || {})
        .map(([k, v]) => `<div class="approval-arg"><span class="arg-path">${escapeHtml(k)}</span> ${escapeHtml(fmtValue(v).slice(0, 300))}</div>`)
        .join('');
    const diff = (a.diff || []).map(d => {
        if (d.change === 'added') return `<div class="diff-row diff-added">+ ${escapeHtml(d.path)}: ${escapeHtml(fmtValue(d.after))}</div>`;
        if (d.change === 'removed') return `<div class="diff-row diff-removed">- ${escapeHtml(d.path)}: ${escapeHtml(fmtValue(d.before))}</div>`;
        return `<div class="diff-row diff-changed">~ ${escapeHtml(d.path)}: ${escapeHtml(fmtValue(d.before))} &rarr; ${escapeHtml(fmtValue(d.after))}</div>`;
    }).join('');
    const diffHtml = a.diff_from
        ? `<div class="approval-section"><div class="expand-label">Changed since ${escapeHtml(a.diff_from)}</div>${diff || '<div class="diff-row">no argument changes</div>'}</div>`
        : '';
    const expires = a.status === 'pending' && a.expires_at
        ? `<span class="approval-expiry" data-expires="${Number(a.expires_at)}"></span>` : '';
    const buttons = a.status === 'pending' ? `
        <div class="approval-actions">
            <button class="btn-approve" data-answer="true">Approve</button>
            <button class="btn-deny" data-answer="false">Deny</button>
        </div>` : '';
    const outcome = a.status !== 'pending'
        ? `<div class="approval-outcome">${a.reason === 'timeout' ? 'No answer in time, denied' : (a.status === 'approved' ? 'Approved' : 'Denied')}${a.resolved_by && a.reason !== 'timeout' ? ' by ' + escapeHtml(a.resolved_by === 'session' ? 'this dashboard session' : a.resolved_by) : ''}${a.note ? ': ' + escapeHtml(a.note) : ''}</div>` : '';

    card.innerHTML = `
        <div class="approval-head">
            <span class="approval-status status-${escapeHtml(a.status)}">${approvalStatusLabel(a)}</span>
            <span class="decision-tool">${escapeHtml(a.tool_name || '')}${a.agent ? ' (' + escapeHtml(a.agent) + ')' : ''}</span>
            ${expires}
        </div>
        <div class="decision-rule">Policy rule: ${escapeHtml(a.policy_rule_id || '')} &middot; ${escapeHtml(a.approval_id)}</div>
        <div class="approval-section">${args || '<div class="approval-arg">no arguments</div>'}</div>
        ${diffHtml}
        ${outcome}
        ${buttons}`;
    card.querySelectorAll('button[data-answer]').forEach(btn => {
        btn.addEventListener('click', () => answerApproval(a.approval_id, btn.dataset.answer === 'true', card));
    });
    tickApprovalExpiry();

    const decision = document.querySelector(`.decision-card[data-approval-id="${CSS.escape(a.approval_id)}"] .decision-action`);
    if (decision && a.status !== 'pending') decision.textContent = approvalStatusLabel(a);
}

async function answerApproval(id, approve, card) {
    card.querySelectorAll('button').forEach(b => { b.disabled = true; });
    try {
        const resp = await fetch(`${BASE_PATH}/api/approvals/${encodeURIComponent(id)}`, {
            method: 'POST', headers: apiHeaders(), body: JSON.stringify({ approve }),
        });
        const data = await resp.json().catch(() => ({}));
        if (resp.ok || resp.status === 409) {
            renderApproval(data);
        } else {
            card.querySelector('.approval-outcome')?.remove();
            card.insertAdjacentHTML('beforeend', `<div class="approval-outcome approval-error">${escapeHtml(data.detail || data.error || 'HTTP ' + resp.status)}</div>`);
            card.querySelectorAll('button').forEach(b => { b.disabled = false; });
        }
    } catch (e) {
        card.querySelectorAll('button').forEach(b => { b.disabled = false; });
    }
}

function tickApprovalExpiry() {
    const now = Date.now() / 1000;
    document.querySelectorAll('.approval-expiry[data-expires]').forEach(el => {
        const left = Math.max(0, Math.round(Number(el.dataset.expires) - now));
        el.textContent = left > 0 ? `${left}s left` : 'expiring';
    });
}
setInterval(tickApprovalExpiry, 1000);

async function loadApprovals() {
    try {
        const q = IS_APP_SESSION ? `?session=${encodeURIComponent(SESSION_ID)}` : '';
        const resp = await fetch(`${BASE_PATH}/api/approvals${q}`, { headers: apiHeaders() });
        if (!resp.ok) return;
        const data = await resp.json();
        (data.approvals || []).forEach(renderApproval);
    } catch (e) {
        console.error('Failed to load approvals:', e);
    }
}

// ---- Render: Agent Activity (Left Panel) ----
// Generic renderer: adapts to ANY agent system based on data shape, not event names.

function renderActivityCard(event) {
    hideEmpty('activityEmpty');
    const list = document.getElementById('activityList');

    const card = document.createElement('div');
    const data = event.data || {};
    const elapsed = `<span class="elapsed-badge">${Number(event.elapsed || 0).toFixed(1)}s</span>`;
    const taskTag = event.task_id ? `<span class="task-tag">${escapeHtml(String(event.task_id))}</span>` : '';
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
            const agentName = String(event.agent || data.agent || data.name || 'agent').toUpperCase();
            card.className = `event-card agent-start-card`;
            card.style.borderLeftColor = agentColor(agentName);
            body = `
                <div class="agent-start-row">
                    ${iconSvg('zap')}<span class="agent-name" style="color:${agentColor(agentName)}">${escapeHtml(agentName)}</span>${source}${taskTag}${elapsed}
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
                    <span class="eval-score ${scoreClass}">${escapeHtml(String(score))}${typeof score === 'number' ? '/10' : ''}</span>
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
    return escapeHtml(String(eventType ?? '').replace(/_/g, ' '));
}

// ---- Render: Guardian Decisions (Right Panel) ----

function renderDecisionCard(event) {
    hideEmpty('decisionEmpty');
    const list = document.getElementById('decisionList');

    const isPending = event.action === 'require_approval';
    const isBlocked = event.action === 'flagged' || event.action === 'blocked' || isPending;
    const card = document.createElement('div');
    card.className = `event-card decision-card ${isPending ? 'pending' : (isBlocked ? 'flagged' : 'allowed')}`;
    if (event.decision_id) card.dataset.decisionId = event.decision_id;
    if (event.approval_id) card.dataset.approvalId = event.approval_id;
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

    const iconClass = isPending ? 'pending-icon' : (isBlocked ? 'flagged-icon' : 'allowed-icon');
    const actionClass = isPending ? 'pending-text' : (isBlocked ? 'flagged-text' : 'allowed-text');
    const actionLabel = isPending ? 'NEEDS APPROVAL' : String(event.action || '').toUpperCase();

    // Where the decision was made: observed on the passive tap (cannot stop
    // anything), monitor mode (enforcement off) or enforced inline.
    let modeHtml = '';
    if (event.observed) {
        modeHtml = '<span class="mode-badge observed" title="Seen on the observer tap. The tap is a copy of the traffic and cannot stop the call.">OBSERVED</span>';
    } else if (event.mode === 'monitor') {
        modeHtml = '<span class="mode-badge observed" title="Policy is in monitor mode: the call was let through.">MONITOR</span>';
    } else if (event.enforced) {
        modeHtml = '<span class="mode-badge enforced" title="Decided inline by the policy engine.">ENFORCED</span>';
    }
    const effectHtml = event.effect && event.effect !== 'allow'
        ? `<span class="mode-badge effect">policy: ${escapeHtml(event.effect)}</span>` : '';

    // Threat level badge
    let threatHtml = '';
    if (event.threat_level && event.threat_level !== 'none') {
        threatHtml = `<span class="threat-level ${event.threat_level}">${event.threat_level.toUpperCase()}</span>`;
    } else if (!isBlocked) {
        threatHtml = '<span class="threat-level none">SAFE</span>';
    }

    // OWASP badges: LLM Top 10 (2025) and Agentic Top 10 (2026)
    let owaspHtml = '';
    const llmId = event.owasp_llm || event.owasp_id || '';
    if (llmId) {
        owaspHtml += `<span class="owasp-badge" title="${escapeHtml(owaspLabel('owasp_llm', llmId))}">${escapeHtml(llmId)}</span>`;
    }
    if (event.owasp_agentic) {
        owaspHtml += `<span class="owasp-badge" title="${escapeHtml(owaspLabel('owasp_agentic', event.owasp_agentic))}">${escapeHtml(event.owasp_agentic)}</span>`;
    }

    // Rule name
    let ruleHtml = '';
    if (event.policy_rule_id || event.rule_name) {
        const parts = [];
        if (event.policy_rule_id) parts.push(`Policy rule: ${escapeHtml(event.policy_rule_id)}`);
        if (event.matched_detectors && event.matched_detectors.length) {
            parts.push(`Detectors: ${escapeHtml(event.matched_detectors.join(', '))}`);
        } else if (event.rule_name && !event.policy_rule_id) {
            parts.push(`Rule: ${escapeHtml(event.rule_name)}`);
        }
        ruleHtml = `<div class="decision-rule">${parts.join(' &middot; ')}</div>`;
    }

    // Reason
    let reasonHtml = '';
    if (event.reason) {
        reasonHtml = `<div class="decision-reason">${escapeHtml(event.reason)}</div>`;
    }

    // Source app badge
    const srcName = event.details?._source || '';
    const srcHtml = srcName ? `<span class="source-badge" style="background:${sourceColor(srcName)}">${escapeHtml(srcName)}</span>` : '';

    const eventLabel = event.tool_name && !String(event.tool_name).startsWith('guardian.')
        ? escapeHtml(event.tool_name) : formatEventType(event.event_type);
    const agentLabel = event.agent ? ` (${event.agent})` : '';

    // Details (exclude _source from display)
    let detailsHtml = '';
    if (event.details && Object.keys(event.details).length > 0) {
        const filtered = Object.fromEntries(Object.entries(event.details).filter(([k]) => k !== '_source'));
        if (Object.keys(filtered).length > 0) {
            detailsHtml = `<div class="decision-args">${escapeHtml(JSON.stringify(filtered, null, 2))}</div>`;
        }
    }

    // Build expandable detail panel for flagged cards
    let expandHtml = '';
    if (isBlocked) {
        const remediation = getRemediation(event.rule_name);
        const owaspSections = [['owasp_llm', llmId], ['owasp_agentic', event.owasp_agentic]]
            .filter(([kind, id]) => id && getOwaspInfo(kind, id))
            .map(([kind, id]) => `
            <div class="expand-section">
                <div class="expand-label">OWASP ${escapeHtml(id)}: ${escapeHtml(owaspLabel(kind, id))}</div>
                <div class="expand-text">${escapeHtml(getOwaspInfo(kind, id))}</div>
            </div>`).join('');

        expandHtml = `
        <div class="decision-expand" style="display:none">
            <div class="expand-section">
                <div class="expand-label">What happened</div>
                <div class="expand-text">${escapeHtml(event.reason || '')}</div>
            </div>
            ${owaspSections}
            <div class="expand-section">
                <div class="expand-label">How to fix</div>
                <div class="expand-text">${escapeHtml(remediation)}</div>
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
            <span class="decision-action ${actionClass}">${actionLabel}</span>
            ${srcHtml}
            <span class="decision-tool">${eventLabel}${agentLabel}</span>
            ${isBlocked ? '<span class="expand-arrow">&#9662;</span>' : ''}
        </div>
        <div class="decision-badges">
            ${threatHtml}${modeHtml}${effectHtml}${owaspHtml}
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
    node.className = `timeline-node ${isBlocked ? 'flagged' : 'allowed'}`;

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
    if (!el) return;
    const num = el.querySelector('.counter-num');
    if (!num) return;
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
    if (IS_APP_SESSION) return;  // API-key sessions have no observed targets
    try {
        const resp = await fetch(`${BASE_PATH}/api/targets`, { headers: apiHeaders() });
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
            headers: apiHeaders(),
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
            headers: apiHeaders(),
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
        'blocked_address': 'GuardianAI only connects to public addresses. For a local app, run GuardianAI yourself with <code>ALLOW_PRIVATE_TARGETS=true</code>.',
        'invalid_scheme': 'Use an http(s) app URL; GuardianAI connects to its /ws-observe WebSocket.',
        'invalid_url': 'Check the URL. Credentials in the URL are not supported.',
        'dns_failed': 'The hostname did not resolve. Check for typos.',
        'redirect_refused': 'Register the final URL your app redirects to (for example with or without www).',
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
        await fetch(`${BASE_PATH}/api/targets/${encodeURIComponent(name)}`, { method: 'DELETE', headers: apiHeaders() });
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
    let checked, flagged, allowed, blocked, byRule, bySeverity;
    if (selectedApp !== '__all' && event.per_app && event.per_app[selectedApp]) {
        const appStats = event.per_app[selectedApp];
        checked = appStats.checked || 0;
        flagged = appStats.flagged || 0;
        allowed = appStats.allowed || 0;
        blocked = appStats.blocked || 0;
        byRule = appStats.by_rule || {};
        bySeverity = appStats.by_severity || {};
    } else {
        checked = event.total_checked || 0;
        flagged = event.total_flagged || 0;
        allowed = event.total_allowed || 0;
        blocked = event.total_blocked || 0;
        byRule = event.by_rule || {};
        bySeverity = event.by_severity || {};
    }

    const ruleChips = Object.entries(byRule).map(([rule, count]) =>
        `<span class="summary-chip summary-chip-flagged">${escapeHtml(rule)}: ${count}</span>`
    ).join('');

    const sevChips = Object.entries(bySeverity).map(([sev, count]) =>
        `<span class="summary-chip severity-${sev}">${sev.toUpperCase()}: ${count}</span>`
    ).join('');

    const statusClass = flagged > 0 ? 'summary-warning' : 'summary-clean';
    const statusIcon = flagged > 0
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
            <span class="summary-stat summary-flagged-count">${flagged} flagged</span>
            ${blocked > 0 ? `<span class="summary-stat summary-flagged-count">${blocked} blocked</span>` : ''}
        </div>
        ${sevChips || ruleChips ? `<div class="summary-chips">${sevChips}${ruleChips}</div>` : ''}
    `;

    // Update header counters
    updateCounter('flaggedCounter', flagged);
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
    if (filter === 'flagged') return ['flagged', 'blocked', 'require_approval'].includes(card.dataset.action);
    if (filter === 'require_approval') return card.dataset.action === 'require_approval';
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

function owaspLabel(kind, id) {
    return TAXONOMY[kind]?.items?.[id]?.label || '';
}

function getOwaspInfo(kind, id) {
    return TAXONOMY[kind]?.items?.[id]?.description || '';
}

function getRemediation(ruleName) {
    return TAXONOMY.rules?.[ruleName]?.remediation
        || 'Review the flagged content and the policy rule that matched it.';
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
loadTaxonomy();
connectWebSocket();
loadTargets();
loadApprovals();
