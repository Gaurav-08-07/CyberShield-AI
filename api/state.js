// Vercel Serverless Function: GET /api/state
// Generates realistic simulation data on every call (stateless design for Vercel).
// The original dashboard expects: { stats, logs, alerts, queueItems, topIps, stackItems }

const ACTIONS = ['LOGIN_ATTEMPT', 'PORT_SCAN', 'PRIVILEGE_ESCALATION', 'DATA_EXPORT', 'DATA_READ', 'FILE_UPLOAD', 'FIREWALL_BLOCK', 'SSH_CONNECTION'];
const STATUSES = ['SUCCESS', 'FAILED', 'BLOCKED'];
const KNOWN_MALICIOUS = ['185.220.101.42', '45.33.32.156', '198.51.100.77', '203.0.113.66', '91.219.236.13'];
const INTERNAL_IPS   = ['10.0.1.15', '10.0.1.22', '10.0.2.5', '10.0.3.7', '172.16.0.100'];
const PORTS = [22, 80, 443, 3306, 8080, 3389, 21, 53, 8443, 9200];

function rnd(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function pick(arr)      { return arr[Math.floor(Math.random() * arr.length)]; }

function randomIP() {
    if (Math.random() < 0.15) return pick(KNOWN_MALICIOUS);
    if (Math.random() < 0.55) return pick(INTERNAL_IPS);
    return `${rnd(1,223)}.${rnd(0,255)}.${rnd(0,255)}.${rnd(1,254)}`;
}

function severityFor(action, status) {
    if (action === 'PRIVILEGE_ESCALATION') return rnd(8, 10);
    if (action === 'DATA_EXPORT')          return rnd(7, 10);
    if (action === 'PORT_SCAN')            return rnd(5, 8);
    if (status  === 'FAILED')              return rnd(5, 8);
    if (status  === 'BLOCKED')             return rnd(4, 7);
    return rnd(1, 4);
}

function generateLogEvent(id) {
    const ip      = randomIP();
    const action  = pick(ACTIONS);
    const status  = pick(STATUSES);
    const port    = pick(PORTS);
    const sev     = severityFor(action, status);
    return { id, timestamp: Date.now(), ip, action, status, port, severity: sev };
}

function generateAlert(id, triggerLog) {
    const types = [
        { type: 'Brute Force Detected',       message: `${rnd(8,25)} failed logins from ${triggerLog.ip}`, details: `Port: ${triggerLog.port} | Severity: ${triggerLog.severity}` },
        { type: 'DDoS Indicator',              message: `High traffic volume from ${triggerLog.ip}`,        details: `Port: 80 | Rate: ${rnd(40,120)} req/s` },
        { type: 'Privilege Escalation Chain',  message: `Escalation detected for IP ${triggerLog.ip}`,      details: `User → root | Port: 22` },
        { type: 'Port Scan Detected',          message: `${rnd(10,30)} ports probed by ${triggerLog.ip}`,   details: `TCP sweep | Window: 30s` },
        { type: 'Data Exfiltration Alert',     message: `Large outbound transfer from ${triggerLog.ip}`,    details: `Port: 443 | Bytes: ${rnd(10,500)}MB` },
    ];
    const t = pick(types);
    return { id, timestamp: Date.now(), type: t.type, message: t.message, details: t.details };
}

// Simple in-memory accumulator per lambda warm instance
// (resets on cold start, but grows naturally within a session)
let _processed = 0;
let _threats   = 0;
let _topIps    = {};

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') return res.status(200).end();

    // Generate a small batch of logs this tick
    const batchSize = rnd(2, 6);
    const logs      = [];
    for (let i = 0; i < batchSize; i++) {
        _processed++;
        logs.push(generateLogEvent(_processed));
    }

    // Accumulate IP frequencies
    for (const log of logs) {
        _topIps[log.ip] = (_topIps[log.ip] || 0) + 1;
    }

    // Maybe generate an alert (~20% chance per tick)
    const alerts = [];
    if (Math.random() < 0.20 && logs.length > 0) {
        _threats++;
        alerts.push(generateAlert(_threats, pick(logs)));
    }

    // Build queue items (last N logs, formatted for dashboard)
    const queueItems = logs.map(l => ({
        ip:       l.ip,
        action:   l.action,
        severity: l.severity,
        status:   l.status
    }));

    // Build stack items (high-severity events only)
    const stackItems = logs
        .filter(l => l.severity >= 6)
        .map(l => ({ ip: l.ip, action: l.action, severity: l.severity }));

    // Top IPs sorted by hit count
    const topIps = Object.entries(_topIps)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([ip, count]) => ({ ip, count }));

    const queueSize = rnd(1, Math.min(_processed, 40));

    res.status(200).json({
        stats: {
            processed:  _processed,
            threats:    _threats,
            queueSize:  queueSize,
            queueTotal: _processed,
            stackDepth: stackItems.length
        },
        logs,
        alerts,
        queueItems,
        topIps,
        stackItems
    });
};
