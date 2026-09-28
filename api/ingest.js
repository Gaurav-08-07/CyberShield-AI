// Vercel Serverless Function: POST /api/ingest
module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(455).json({ status: 'error', message: 'Method not allowed' });
    }

    try {
        const events = req.body || [];
        const count = Array.isArray(events) ? events.length : 0;

        let threats = 0;
        if (Array.isArray(events)) {
            events.forEach(ev => {
                if (ev.severity >= 8 || ev.status === 'FAILED' || ev.action === 'PRIVILEGE_ESCALATION') {
                    threats++;
                }
            });
        }

        return res.status(200).json({
            status: 'ok',
            ingested: count,
            alertsGenerated: threats
        });
    } catch (e) {
        return res.status(500).json({ status: 'error', message: e.message });
    }
};
