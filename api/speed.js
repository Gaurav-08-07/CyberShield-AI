// Vercel Serverless Function: GET /api/speed
module.exports = (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({ status: 'ok' });
};
