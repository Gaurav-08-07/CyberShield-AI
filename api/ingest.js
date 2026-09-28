// Vercel Serverless Function: POST /api/ingest
// Receives parsed log events from the frontend file analyzer,
// runs threat detection, and returns counts so the dashboard can display results.

const THREAT_RULES = [
    { name: 'BRUTE_FORCE',           check: ev => ev.action === 'LOGIN_ATTEMPT' && ev.status === 'FAILED' && ev.severity >= 5 },
    { name: 'PRIVILEGE_ESCALATION',  check: ev => ev.action === 'PRIVILEGE_ESCALATION' },
    { name: 'DATA_EXFILTRATION',     check: ev => ev.action === 'DATA_EXPORT' && ev.severity >= 8 },
    { name: 'PORT_SCAN',             check: ev => ev.action === 'PORT_SCAN' && ev.severity >= 5 },
    { name: 'HIGH_SEVERITY',         check: ev => ev.severity >= 9 },
];

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') return res.status(200).end();

    if (req.method !== 'POST') {
        return res.status(405).json({ status: 'error', message: 'Method not allowed' });
    }

    try {
        const events = Array.isArray(req.body) ? req.body : [];
        const count  = events.length;

        // Count unique threat detections
        const threatSet = new Set();
        for (const ev of events) {
            for (const rule of THREAT_RULES) {
                if (rule.check(ev)) threatSet.add(rule.name);
            }
        }

        return res.status(200).json({
            status:          'ok',
            ingested:        count,
            alertsGenerated: threatSet.size
        });
    } catch (e) {
        return res.status(500).json({ status: 'error', message: e.message });
    }
};
