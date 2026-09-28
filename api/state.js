// Vercel Serverless Function: GET /api/state
let state = {
    processed: 0,
    threats: 0,
    queueSize: 0,
    queueTotal: 0,
    stackDepth: 0,
    logs: [],
    alerts: [],
    queueItems: [],
    topIps: [
        { ip: "192.168.1.10", count: 42 },
        { ip: "10.0.0.5", count: 35 },
        { ip: "172.16.0.50", count: 28 },
        { ip: "45.33.22.11", count: 19 },
        { ip: "104.22.3.44", count: 14 }
    ],
    stackItems: []
};

module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Generate lightweight mock updates if empty
    state.processed += Math.floor(Math.random() * 4) + 1;
    state.queueTotal = state.processed;
    state.queueSize = Math.floor(Math.random() * 8) + 1;

    res.status(200).json({
        stats: {
            processed: state.processed,
            threats: state.threats,
            queueSize: state.queueSize,
            queueTotal: state.queueTotal,
            stackDepth: state.stackDepth
        },
        logs: state.logs.slice(-20),
        alerts: state.alerts.slice(-10),
        queueItems: state.queueItems.slice(-10),
        topIps: state.topIps,
        stackItems: state.stackItems.slice(-8)
    });
};
