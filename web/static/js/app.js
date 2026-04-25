// ================================================================
// Satur8 — Frontend Application
// Performance-optimized WebSocket client with panel routing
// ================================================================

'use strict';

// ── State ────────────────────────────────────────────────────────
let socket;
let isRunning = false;
let currentView = 'dashboard';
let baselineCountdownInterval = null;

// Keyed stores to avoid full DOM rebuilds
const seenPacketNums = new Set();
const deviceRowMap   = new Map();

const MAX_ALERTS  = 100;
const MAX_PACKETS = 60;

// ── Init ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initSocket();
    initNav();
    initButtons();
    initBaseline();
    setStatus('init');
    ['deauthEmpty', 'mitmEmpty', 'rogueEmpty', 'systemEmpty', 'alertsEmptyFull', 'packetsEmpty', 'clientsEmpty']
        .forEach(id => showEmpty(id, true));
});

// ── Socket ───────────────────────────────────────────────────────
function initSocket() {
    socket = io();

    socket.on('connect', () => {
        setStatus('ready');
        requestStats();
    });

    socket.on('disconnect', () => setStatus('offline'));

    socket.on('stats',            (data)    => applyStats(data));
    socket.on('alert',            (alert)   => addAlertCard(alert, true));
    socket.on('baseline_status',  (status)  => applyBaselineStatus(status));
    socket.on('packets', (packets) => requestAnimationFrame(() => addPacketRows(packets)));
    socket.on('devices', (devices) => requestAnimationFrame(() => updateClientsTable(devices)));

    setInterval(() => socket?.connected && requestStats(),                              2000);
    setInterval(() => socket?.connected && isRunning && socket.emit('request_packets'), 3000);
    setInterval(() => socket?.connected && isRunning && socket.emit('request_devices'), 5000);
}

function requestStats() { socket?.emit('request_stats'); }

// ── Navigation ───────────────────────────────────────────────────
function initNav() {
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            switchView(item.dataset.view);
        });
    });
}

function switchView(view) {
    if (view === currentView) return;
    currentView = view;
    document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
    document.querySelectorAll('.view').forEach(el => el.classList.toggle('active', el.id === `view-${view}`));
    document.getElementById('topbarPage').textContent = view;
}

// ── Buttons ──────────────────────────────────────────────────────
function initButtons() {
    document.getElementById('btnToggle').addEventListener('click', toggleMonitoring);

    const DASH_FEEDS = ['deauthFeed', 'mitmFeed', 'rogueFeed', 'systemFeed'];
    const EMPTY_IDS  = ['deauthEmpty', 'mitmEmpty', 'rogueEmpty', 'systemEmpty'];

    // Call the server-side clear so alerts don't reappear on page refresh
    const apiClear = (types) => fetch('/api/alerts/clear', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(types ? {types} : {})
    }).catch(() => {});

    const clearDashFeeds = () => {
        DASH_FEEDS.forEach(id => { document.getElementById(id).innerHTML = ''; });
        EMPTY_IDS.forEach(id => showEmpty(id, true));
        setBadge('navAlertBadge', 0);
    };
    const clearFull = () => {
        document.getElementById('alertsFeedFull').innerHTML = '';
        showEmpty('alertsEmptyFull', true);
    };
    const clearAlerts = async () => {
        await apiClear(null);
        clearDashFeeds();
        clearFull();
    };

    document.getElementById('btnClearDeauth')?.addEventListener('click', async () => {
        await apiClear(['DEAUTH_ATTACK']);
        document.getElementById('deauthFeed').innerHTML = '';
        showEmpty('deauthEmpty', true);
    });
    document.getElementById('btnClearMitm')?.addEventListener('click', async () => {
        await apiClear(['ARP_SPOOFING', 'ARP_FLOOD', 'EVIL_TWIN']);
        document.getElementById('mitmFeed').innerHTML = '';
        showEmpty('mitmEmpty', true);
    });
    document.getElementById('btnClearSystem')?.addEventListener('click', async () => {
        await apiClear(['BASELINE_COMPLETE', 'SCAN_STARTED', 'SCAN_STOPPED', 'MONITOR_MODE_FALLBACK', 'OUI_DB_LOADED', 'OUI_DB_MISSING']);
        document.getElementById('systemFeed').innerHTML = '';
        showEmpty('systemEmpty', true);
    });
    document.getElementById('btnClearRogue')?.addEventListener('click', async () => {
        await apiClear(['KARMA_ATTACK', 'ROGUE_BEACON', 'PINEAPPLE_KARMA', 'PINEAPPLE_MULTI_SSID', 'SUSPICIOUS_DEVICE', 'SUSPICIOUS_SSID', 'SUSPICIOUS_ADAPTER']);
        document.getElementById('rogueFeed').innerHTML = '';
        showEmpty('rogueEmpty', true);
    });
    document.getElementById('btnClearAlertsFull')?.addEventListener('click', clearAlerts);
}

// ── Toggle monitoring ────────────────────────────────────────────
async function toggleMonitoring() {
    const btn = document.getElementById('btnToggle');
    try {
        if (!isRunning) {
            const baselineOn = document.getElementById('baselineToggle')?.checked || false;
            const durInput   = document.getElementById('baselineDuration');
            const duration   = Math.max(30, Math.min(3600, parseInt(durInput?.value) || 300));

            const body = baselineOn
                ? JSON.stringify({ baseline: true, baseline_duration: duration })
                : '{}';

            const d = await (await fetch('/api/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body,
            })).json();

            if (d.status === 'started') {
                isRunning = true;
                btn.textContent = 'STOP MONITOR';
                btn.className = 'btn-monitor stop';
                setStatus('active');
                socket.emit('request_packets');
                socket.emit('request_devices');
            }
        } else {
            const d = await (await fetch('/api/stop', { method: 'POST' })).json();
            if (d.status === 'stopped') {
                isRunning = false;
                btn.textContent = 'START MONITOR';
                btn.className = 'btn-monitor start';
                setStatus(socket?.connected ? 'ready' : 'offline');
                // Stop the baseline countdown immediately
                applyBaselineStatus({});
            }
        }
    } catch (err) { console.error('Toggle error:', err); }
}

// ── Status chip ──────────────────────────────────────────────────
function setStatus(state) {
    const chip  = document.getElementById('status');
    const dot   = document.getElementById('sysDot');
    const label = document.getElementById('sysStatusLabel');
    chip.className = 'status-chip';
    dot.className  = 'sys-dot';
    const map = {
        init:    ['', '○ Initializing…', 'Connecting'],
        ready:   ['ready',  '● Ready',      'Ready'],
        active:  ['active', '● Monitoring', 'Active'],
        stopped: ['stopped','● Stopped',    'Stopped'],
        offline: ['',       '○ Disconnected','Offline'],
    };
    const [cls, chipTxt, labelTxt] = map[state] || map.offline;
    if (cls) { chip.classList.add(cls); dot.classList.add(cls === 'ready' ? 'online' : cls); }
    chip.textContent  = chipTxt;
    label.textContent = labelTxt;
}

// ── Stats ─────────────────────────────────────────────────────────
function applyStats(stats) {
    if (!stats) return;

    if (stats.running !== undefined && stats.running !== isRunning) {
        isRunning = stats.running;
        const btn = document.getElementById('btnToggle');
        if (isRunning) {
            btn.textContent = 'STOP MONITOR'; btn.className = 'btn-monitor stop'; setStatus('active');
        } else {
            btn.textContent = 'START MONITOR'; btn.className = 'btn-monitor start';
            setStatus(socket?.connected ? 'ready' : 'offline');
        }
    }

    text('packetCount', fmt(stats.packet_count));
    text('packetCountFull', fmt(stats.packet_count) + ' captured');

    const iface = stats.interface || '—';
    text('interface', iface);
    text('sysIface', iface);

    const warn = document.getElementById('monitorWarning');
    const ch   = document.getElementById('channelStrip');
    if (stats.running) {
        if (stats.monitor_mode === false) {
            document.getElementById('warnIface').textContent = iface;
            warn.style.display = 'inline-block';
        } else { warn.style.display = 'none'; }
        ch.style.display = 'flex';
        text('channelNum', stats.current_channel ?? '—');
        text('hoppingStatus', stats.channel_hopping ? 'ON' : 'OFF');
    } else { warn.style.display = 'none'; ch.style.display = 'none'; }

    if (stats.alerts) {
        text('alertCount', fmt(stats.alerts.total));
        const by = stats.alerts.by_type || {};
        text('deauthCount',    fmt(by.DEAUTH_ATTACK || by.deauth_attack || 0));
        text('mitmCount',      fmt((by.ARP_SPOOFING || by.arp_spoofing || 0) + (by.ARP_FLOOD || by.arp_flood || 0) + (by.EVIL_TWIN || 0)));
        // Pineapple tile = unique suspicious physical devices, not sum of alert events
        // (stats.devices.suspicious_count is updated below)
    }
    if (stats.deauth)  text('deauthPairs', fmt(stats.deauth.tracked_pairs));
    if (stats.mitm) {
        text('trackedMacs', fmt(stats.mitm.tracked_macs));
        text('ssidsTracked', fmt(stats.mitm.ssids_tracked));
        text('evilTwinsDetected', fmt(stats.mitm.wireless_threats));
    }
    if (stats.devices) {
        const total = stats.devices.total_discovered || 0;
        const susp  = stats.devices.suspicious_count || 0;
        text('deviceCount', fmt(total));
        text('suspiciousDevices', fmt(susp));
        text('pineappleCount', fmt(susp));   // unique suspicious devices, not alert counts
        text('clientCount', `${fmt(total)} device${total !== 1 ? 's' : ''}`);
        setBadge('navClientBadge', total);
    }
    const ouiEl = document.getElementById('ouiDbStatus');
    if (ouiEl && stats.oui_db) {
        const db = stats.oui_db;
        if (db.loaded) {
            ouiEl.innerHTML = `<span style="color:var(--green)">${(db.entry_count || 0).toLocaleString()} entries</span>`;
        } else {
            ouiEl.innerHTML = `<span style="color:var(--orange)" title="Place oui.txt in project root">Not loaded — drop oui.txt in project root</span>`;
        }
    }
}

// ── Alert type → dashboard feed routing ─────────────────────────
const DEAUTH_TYPES = new Set(['DEAUTH_ATTACK']);
const MITM_TYPES   = new Set(['ARP_SPOOFING', 'ARP_FLOOD', 'EVIL_TWIN']);
const ROGUE_TYPES  = new Set(['KARMA_ATTACK', 'ROGUE_BEACON', 'PINEAPPLE_KARMA', 'PINEAPPLE_MULTI_SSID', 'SUSPICIOUS_DEVICE', 'SUSPICIOUS_SSID', 'SUSPICIOUS_ADAPTER']);
const SYSTEM_TYPES = new Set(['BASELINE_COMPLETE', 'SCAN_STARTED', 'SCAN_STOPPED', 'MONITOR_MODE_FALLBACK', 'OUI_DB_LOADED', 'OUI_DB_MISSING']);
// Anything not in the above sets also falls through to rogueFeed
function getDashFeedId(type) {
    if (DEAUTH_TYPES.has(type)) return 'deauthFeed';
    if (MITM_TYPES.has(type))   return 'mitmFeed';
    if (SYSTEM_TYPES.has(type)) return 'systemFeed';
    return 'rogueFeed';
}
function getDashEmptyId(type) {
    if (DEAUTH_TYPES.has(type)) return 'deauthEmpty';
    if (MITM_TYPES.has(type))   return 'mitmEmpty';
    if (SYSTEM_TYPES.has(type)) return 'systemEmpty';
    return 'rogueEmpty';
}

// ── Alert cards ──────────────────────────────────────────────────
function addAlertCard(alert, prepend) {
    const isSystem = SYSTEM_TYPES.has(alert.type);
    const card = buildAlertCard(alert);
    const dashId  = getDashFeedId(alert.type);
    const emptyId = getDashEmptyId(alert.type);
    const dash = document.getElementById(dashId);
    const full = document.getElementById('alertsFeedFull');
    showEmpty(emptyId, false);
    // Build a second independent card for the dashboard column (cloneNode loses listeners)
    const dashCard = buildAlertCard(alert);
    if (prepend) {
        dash.insertBefore(dashCard, dash.firstChild);
        // System events don't appear in the security Alerts view
        if (!isSystem) { showEmpty('alertsEmptyFull', false); full.insertBefore(card, full.firstChild); }
    } else {
        dash.appendChild(dashCard);
        if (!isSystem) { showEmpty('alertsEmptyFull', false); full.appendChild(card); }
    }
    while (dash.children.length > MAX_ALERTS) dash.removeChild(dash.lastChild);
    // Badge counts only security alerts (full feed only contains security alerts now)
    if (!isSystem) setBadge('navAlertBadge', full.children.length);
    if (alert.severity === 'critical' || alert.severity === 'high') pushNotification(alert);
}

function buildAlertCard(alert) {
    const div  = document.createElement('div');
    const typeClass = 'type-' + (alert.type || '').toLowerCase().replace(/_/g, '-');
    div.className = `alert-card ${alert.severity || ''} ${typeClass}`;
    const time = new Date(alert.timestamp).toLocaleTimeString();
    let dataHtml = '';
    if (alert.data && Object.keys(alert.data).length > 0) {
        const c = {};
        for (const [k, v] of Object.entries(alert.data)) {
            if (Array.isArray(v)) c[k] = v.slice(0, 20).map(s => typeof s === 'string' ? s.replace(/[\x00-\x1F\x7F]/g, '').slice(0, 80) : s);
            else if (typeof v === 'string') c[k] = v.replace(/[\x00-\x1F\x7F]/g, '').slice(0, 120);
            else c[k] = v;
        }
        dataHtml = `<div class="ac-data" style="display:none">${esc(JSON.stringify(c, null, 2))}</div>`;
    }
    div.innerHTML = `<div class="ac-header"><span class="ac-type ${esc(alert.severity || '')} ${typeClass}">${esc(alert.type || '')}</span><span class="ac-msg">${esc(alert.message || '')}</span><span class="ac-time">${time}</span>${dataHtml ? '<button class="ac-toggle" title="Show details">&#9656;</button>' : ''}</div>${dataHtml}`;
    // Wire the toggle button
    const btn = div.querySelector('.ac-toggle');
    if (btn) {
        btn.addEventListener('click', () => {
            const data = div.querySelector('.ac-data');
            const open = data.style.display !== 'none';
            data.style.display = open ? 'none' : 'block';
            btn.innerHTML = open ? '&#9656;' : '&#9662;';
            btn.title = open ? 'Show details' : 'Hide details';
        });
    }
    return div;
}

// ── Packet table ─────────────────────────────────────────────────
function addPacketRows(packets) {
    if (!packets?.length) return;
    const tbody = document.getElementById('packetsBody');
    const frag  = document.createDocumentFragment();
    let added = 0;
    for (let i = packets.length - 1; i >= 0; i--) {
        const p = packets[i];
        if (!p || seenPacketNums.has(p.number)) continue;
        if (p.type === 'Unknown' && !p.src && !p.info) continue;
        seenPacketNums.add(p.number);
        frag.append(buildPacketRow(p));
        added++;
    }
    if (!added) return;
    tbody.insertBefore(frag, tbody.firstChild);
    while (tbody.rows.length > MAX_PACKETS) tbody.deleteRow(tbody.rows.length - 1);
    showEmpty('packetsEmpty', !tbody.rows.length);
}

function buildPacketRow(p) {
    const tr = document.createElement('tr');
    const t  = new Date(p.timestamp * 1000).toLocaleTimeString();
    tr.innerHTML = `<td class="td-mute td-mono">#${p.number}</td><td><span class="pkt-type-badge ${esc(p.type)}">${esc(p.type)}</span></td><td class="td-mono">${esc(p.src || '—')}</td><td class="td-mono">${esc(p.dst || '—')}</td><td class="td-dim">${esc(p.info || '—')}</td><td class="td-mute">${t}</td>`;
    return tr;
}

// ── Clients table ─────────────────────────────────────────────────
function updateClientsTable(devices) {
    if (!devices) return;
    const tbody = document.getElementById('clientsBody');
    devices.sort((a, b) => {
        if (a.suspicious !== b.suspicious) return b.suspicious ? 1 : -1;
        return (b.packet_count || 0) - (a.packet_count || 0);
    });
    const seen = new Set();
    devices.forEach(dev => {
        seen.add(dev.mac);
        if (deviceRowMap.has(dev.mac)) {
            populateDeviceRow(deviceRowMap.get(dev.mac), dev);
            deviceRowMap.get(dev.mac).className = dev.suspicious ? 'suspicious-row' : '';
        } else {
            const tr = document.createElement('tr');
            tr.className = dev.suspicious ? 'suspicious-row' : '';
            populateDeviceRow(tr, dev);
            deviceRowMap.set(dev.mac, tr);
            tbody.appendChild(tr);
        }
    });
    for (const [mac, tr] of deviceRowMap) {
        if (!seen.has(mac)) { tr.remove(); deviceRowMap.delete(mac); }
    }
    showEmpty('clientsEmpty', !tbody.rows.length);
}

function populateDeviceRow(tr, dev) {
    const last  = new Date(dev.last_seen  * 1000).toLocaleTimeString();
    const first = new Date(dev.first_seen * 1000).toLocaleTimeString();

    // Deduplicate and clean SSIDs; strip "[probe] " prefix for display
    const rawSSIDs = (dev.ssids || [])
        .map(s => s.startsWith('[probe] ') ? s.slice(8) : s)
        .map(s => s.replace(/[^\x20-\x7E]/g, '?').slice(0, 32).trim())
        .filter(s => s.length > 0);
    const uniqSSIDs = [...new Set(rawSSIDs)];
    const ssidText  = uniqSSIDs.length === 0 ? '—'
        : uniqSSIDs.slice(0, 3).join(', ') + (uniqSSIDs.length > 3 ? ` +${uniqSSIDs.length - 3} more` : '');

    // Role badge
    const roleRaw = dev.role || dev.type || 'Unknown';
    const roleLow = roleRaw.toLowerCase();
    const roleCls = roleLow.includes('access point') || roleLow === 'ap' ? 'ap'
        : roleLow.includes('rogue') ? 'rogue'
        : roleLow.includes('station') || roleLow.includes('client') ? 'sta'
        : 'unk';

    const vendor    = esc(dev.vendor || 'Unknown');
    const randBadge = dev.is_random ? '<span class="rand-mac" title="Randomized/spoofed MAC">&#8635;</span>' : '';
    const statusBadge = dev.suspicious
        ? '<span class="status-badge warn">SUSPICIOUS</span>'
        : '<span class="status-badge ok">OK</span>';

    tr.innerHTML =
        `<td class="td-mono">${randBadge}${esc(dev.mac)}</td>` +
        `<td class="td-dim vendor-cell" title="${vendor}">${vendor}</td>` +
        `<td><span class="role-badge role-${roleCls}">${esc(roleRaw)}</span></td>` +
        `<td class="td-dim ssid-cell" title="${esc(uniqSSIDs.join(', ') || '—')}">${esc(ssidText)}</td>` +
        `<td class="td-mute td-num">${fmt(dev.packet_count)}</td>` +
        `<td class="td-mute">${first}</td>` +
        `<td class="td-mute">${last}</td>` +
        `<td>${statusBadge}</td>`;
}

// ── Baseline scan ─────────────────────────────────────────────
function initBaseline() {
    // Fetch existing baseline state on load
    fetch('/api/baseline/status').then(r => r.json()).then(applyBaselineStatus).catch(() => {});
}

function applyBaselineStatus(status) {
    if (!status) return;

    const bar       = document.getElementById('baselineStatusBar');
    const progWrap  = document.getElementById('baselineProgressRow');
    const progBar   = document.getElementById('baselineProgressBar');
    const countdown = document.getElementById('baselineCountdown');
    const statusTxt = document.getElementById('baselineStatusText');
    const ssidCount = document.getElementById('baselineSsidCount');

    if (status.mode) {
        // ── Actively scanning ──────────────────────────────
        bar.style.display  = 'flex';
        bar.className      = 'baseline-status-bar scanning';

        if (statusTxt) statusTxt.textContent = 'Scanning environment\u2026';
        if (progWrap)  progWrap.style.display = '';
        if (ssidCount) ssidCount.style.display = 'none';

        // Local countdown ticker
        if (baselineCountdownInterval) clearInterval(baselineCountdownInterval);
        let remaining = status.time_remaining ?? 0;
        const duration = status.duration || remaining;
        const tick = () => {
            if (countdown) countdown.textContent = remaining + 's';
            if (progBar)   progBar.style.width = Math.min(100, Math.round((duration - remaining) / duration * 100)) + '%';
            if (remaining <= 0) { clearInterval(baselineCountdownInterval); baselineCountdownInterval = null; }
            else remaining--;
        };
        tick();
        baselineCountdownInterval = setInterval(tick, 1000);

    } else if (status.complete) {
        // ── Complete ───────────────────────────────────────
        if (baselineCountdownInterval) { clearInterval(baselineCountdownInterval); baselineCountdownInterval = null; }
        bar.style.display  = 'flex';
        bar.className      = 'baseline-status-bar complete';

        if (statusTxt) statusTxt.textContent  = 'Baseline complete \u2014';
        if (progWrap)  progWrap.style.display = 'none';
        if (countdown) countdown.textContent  = '';
        if (ssidCount) { ssidCount.textContent = (status.ssid_count ?? 0) + ' trusted SSIDs'; ssidCount.style.display = ''; }

    } else {
        // ── Idle / hidden ──────────────────────────────────
        if (baselineCountdownInterval) { clearInterval(baselineCountdownInterval); baselineCountdownInterval = null; }
        bar.style.display = 'none';
    }
}

// ── Shared helpers ────────────────────────────────────────────────
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m])); }
function fmt(n) {
    n = n ?? 0;
    if (n >= 1e6)  return (n / 1e6).toFixed(2) + 'M';
    if (n >= 1e4)  return (n / 1e3).toFixed(1) + 'K';
    return n.toLocaleString();
}
function text(id, val) { const el = document.getElementById(id); if (el && el.textContent !== String(val)) el.textContent = val; }
function showEmpty(id, show) { const el = document.getElementById(id); if (el) el.style.display = show ? '' : 'none'; }
function setBadge(id, count) { const el = document.getElementById(id); if (!el) return; el.textContent = count > 999 ? '999+' : String(count); el.style.display = count > 0 ? '' : 'none'; }
function pushNotification(alert) {
    if (!('Notification' in window)) return;
    if (Notification.permission === 'granted') new Notification('Satur8 \u2014 ' + (alert.type || 'Alert'), { body: alert.message });
    else if (Notification.permission !== 'denied') Notification.requestPermission();
}

// ── Load existing alerts on page load ────────────────────────────
setTimeout(async () => {
    try {
        const alerts = await (await fetch('/api/alerts')).json();
        if (Array.isArray(alerts)) [...alerts].reverse().forEach(a => addAlertCard(a, true));
    } catch (e) { console.warn('Initial alerts load failed:', e); }
}, 900);
