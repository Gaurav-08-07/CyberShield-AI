/* ============================================================
   dashboard.js
   UI controller – initialises the simulation, runs the main
   loop, updates every panel, and renders data-structure visuals.
   ============================================================ */

class Dashboard {
    constructor() {
        this.generator = new LogGenerator();
        this.analyzer  = new ThreatAnalyzer();
        this.running   = false;
        this.loopId    = null;
        this.speed     = 5;              // events per tick
        this.tickMs    = 300;            // ms between ticks
        this.logFeed   = [];             // displayed log lines
        this.maxFeedLines = 80;

        // Chart.js instances
        this.timelineChart = null;
        this.attackChart   = null;

        // Canvas for BST
        this.bstCanvas = null;
        this.bstCtx    = null;
    }

    // ─── Bootstrap ───────────────────────────────────────────

    init() {
        this._bindControls();
        this._initCharts();
        this._initBSTCanvas();
        this._renderEmpty();
        this._updateClock();
        setInterval(() => this._updateClock(), 1000);
    }

    _bindControls() {
        document.getElementById('btn-start').addEventListener('click', () => this.start());
        document.getElementById('btn-stop').addEventListener('click', () => this.stop());
        document.getElementById('btn-reset').addEventListener('click', () => this.reset());
        document.getElementById('btn-theme').addEventListener('click', () => {
            document.body.classList.toggle('light-mode');
            const isLight = document.body.classList.contains('light-mode');
            document.getElementById('btn-theme').innerHTML = isLight ? '🌙 Dark Mode' : '☀️ Light Mode';
            this._updateBSTViz(); // Redraw canvas for theme changes
            if(this.timelineChart) this.timelineChart.update();
            if(this.attackChart) this.attackChart.update();
        });
        document.getElementById('speed-slider').addEventListener('input', (e) => {
            this.speed = parseInt(e.target.value, 10);
            document.getElementById('speed-value').textContent = this.speed;
        });
    }

    start() {
        if (this.running) return;
        this.running = true;
        document.getElementById('btn-start').disabled = true;
        document.getElementById('btn-stop').disabled = false;
        document.getElementById('status-indicator').classList.add('active');
        document.getElementById('status-text').textContent = 'SCANNING';
        this.loopId = setInterval(() => this._tick(), this.tickMs);
    }

    stop() {
        this.running = false;
        clearInterval(this.loopId);
        document.getElementById('btn-start').disabled = false;
        document.getElementById('btn-stop').disabled = true;
        document.getElementById('status-indicator').classList.remove('active');
        document.getElementById('status-text').textContent = 'PAUSED';
    }

    reset() {
        this.stop();
        this.generator = new LogGenerator();
        this.analyzer  = new ThreatAnalyzer();
        this.logFeed   = [];
        this._renderEmpty();
        this._clearCharts();
        document.getElementById('status-text').textContent = 'READY';
    }

    // ─── Main Tick ───────────────────────────────────────────

    _tick() {
        // 1. Generate & ingest (add occasional random jitter to build queue)
        let genCount = this.speed;
        if (Math.random() < 0.1) genCount += Math.floor(Math.random() * 10) + 5;
        
        const events = this.generator.generateBatch(genCount);
        this.analyzer.ingest(events);

        // 2. Process & detect (Process slightly faster than base speed, but bursts will queue up)
        const newAlerts = this.analyzer.processQueue(this.speed + 3);

        // 3. Append to log feed
        for (const ev of events) {
            this.logFeed.push(ev);
        }
        if (this.logFeed.length > this.maxFeedLines) {
            this.logFeed = this.logFeed.slice(-this.maxFeedLines);
        }

        // 4. Flash alerts
        if (newAlerts.length > 0) {
            this._flashAlertPanel();
        }

        // 5. Update UI
        this._updateAll();
    }

    // ─── UI Updates ──────────────────────────────────────────

    _updateAll() {
        const stats = this.analyzer.getStats();
        this._updateStats(stats);
        this._updateLogFeed();
        this._updateAlerts();
        this._updateQueueViz();
        this._updateHashViz(stats);
        this._updateBSTViz();
        this._updateStackViz();
        this._updateCharts(stats);
    }

    _renderEmpty() {
        this._updateStats({
            totalProcessed: 0, totalThreats: 0,
            activeIPs: 0, queueDepth: 0, currentRate: 0,
            queueStats: { size: 0, capacity: 500, utilization: '0.0' },
            hashStats: { entries: 0, loadFactor: '0.00', collisions: 0, occupiedBuckets: 0, totalLookups: 0 },
            bstStats: { nodeCount: 0, treeHeight: 0, maxSeverity: 0, minSeverity: 0 },
            stackStats: { depth: 0, totalPushed: 0 },
        });
        document.getElementById('log-feed').innerHTML =
            '<div class="feed-empty">Click <strong>Start Analysis</strong> to begin scanning…</div>';
        document.getElementById('alert-list').innerHTML =
            '<div class="feed-empty">No threats detected yet.</div>';
    }

    // ── Stat Cards ───────────────────────────────────────────

    _updateStats(stats) {
        this._setText('stat-logs', stats.totalProcessed.toLocaleString());
        this._setText('stat-threats', stats.totalThreats.toLocaleString());
        this._setText('stat-ips', stats.activeIPs.toLocaleString());
        this._setText('stat-queue', stats.queueDepth.toLocaleString());

        // Threat rate badge colour
        const threatEl = document.getElementById('stat-threats');
        threatEl.closest('.stat-card')?.classList.toggle('danger', stats.totalThreats > 0);
    }

    // ── Live Log Feed ────────────────────────────────────────

    _updateLogFeed() {
        const container = document.getElementById('log-feed');
        const fragment = document.createDocumentFragment();

        // Only render last 40 for performance
        const visible = this.logFeed.slice(-40);
        for (const ev of visible) {
            const row = document.createElement('div');
            row.className = `log-row severity-${this._sevClass(ev.severity)}`;
            row.innerHTML = `
                <span class="log-time">${this._fmtTime(ev.timestamp)}</span>
                <span class="log-icon">${ev.icon}</span>
                <span class="log-type">${ev.type}</span>
                <span class="log-ip">${ev.srcIP}</span>
                <span class="log-sev" title="Severity ${ev.severity}">${ev.severity}</span>
                <span class="log-msg">${ev.message}</span>
            `;
            fragment.appendChild(row);
        }
        container.innerHTML = '';
        container.appendChild(fragment);
        container.scrollTop = container.scrollHeight;
    }

    // ── Alert Panel ──────────────────────────────────────────

    _updateAlerts() {
        const list = document.getElementById('alert-list');
        const alerts = this.analyzer.alerts.slice(0, 30);
        if (alerts.length === 0) return;

        const fragment = document.createDocumentFragment();
        for (const a of alerts) {
            const card = document.createElement('div');
            card.className = `alert-card alert-${a.level}`;
            card.innerHTML = `
                <div class="alert-header">
                    <span class="alert-icon">${a.icon}</span>
                    <span class="alert-type">${a.attackType.replace(/_/g, ' ')}</span>
                    <span class="alert-level">${a.level.toUpperCase()}</span>
                </div>
                <div class="alert-body">${a.message}</div>
                <div class="alert-meta">
                    <span>${this._fmtTime(a.timestamp)}</span>
                    <span>IP: ${a.srcIP}</span>
                    <span>Session: ${a.sessionId}</span>
                </div>
            `;
            fragment.appendChild(card);
        }
        list.innerHTML = '';
        list.appendChild(fragment);
    }

    _flashAlertPanel() {
        const panel = document.getElementById('alerts-panel');
        panel.classList.add('flash');
        setTimeout(() => panel.classList.remove('flash'), 600);
    }

    // ── Queue Visualization ──────────────────────────────────

    _updateQueueViz() {
        const container = document.getElementById('queue-viz-items');
        const stats = this.analyzer.queue.getStats();
        const items = this.analyzer.queue.getItems(30);

        // Stats line
        document.getElementById('queue-stats').innerHTML =
            `<span>Size: <b>${stats.size}</b>/${stats.capacity}</span>` +
            `<span>Utilization: <b>${stats.utilization}%</b></span>` +
            `<span>Total In: <b>${stats.totalEnqueued}</b></span>`;

        // Item blocks
        const fragment = document.createDocumentFragment();
        for (const item of items) {
            const block = document.createElement('div');
            block.className = `q-block severity-bg-${this._sevClass(item.severity)}`;
            block.title = `${item.type} | Sev: ${item.severity} | ${item.srcIP}`;
            block.textContent = item.severity;
            fragment.appendChild(block);
        }
        container.innerHTML = '';
        container.appendChild(fragment);

        // Progress bar
        const bar = document.getElementById('queue-fill-bar');
        bar.style.width = `${stats.utilization}%`;
        bar.className = `fill-bar ${parseFloat(stats.utilization) > 80 ? 'fill-danger' : parseFloat(stats.utilization) > 50 ? 'fill-warn' : 'fill-ok'}`;
    }

    // ── Hash Table Visualization ─────────────────────────────

    _updateHashViz(stats) {
        // Stats line
        document.getElementById('hash-stats').innerHTML =
            `<span>Entries: <b>${stats.hashStats.entries}</b></span>` +
            `<span>Load: <b>${stats.hashStats.loadFactor}</b></span>` +
            `<span>Collisions: <b>${stats.hashStats.collisions}</b></span>` +
            `<span>Lookups: <b>${stats.hashStats.totalLookups}</b></span>`;

        // Bucket grid
        const grid = document.getElementById('hash-bucket-grid');
        const dist = this.analyzer.ipTable.getBucketDistribution();
        if (grid.children.length !== dist.length) {
            grid.innerHTML = '';
            for (let i = 0; i < dist.length; i++) {
                const cell = document.createElement('div');
                cell.className = 'bucket-cell';
                grid.appendChild(cell);
            }
        }
        for (let i = 0; i < dist.length; i++) {
            const cell = grid.children[i];
            const d = dist[i];
            cell.className = `bucket-cell ${d === 0 ? 'b-empty' : d === 1 ? 'b-one' : d <= 3 ? 'b-few' : 'b-many'}`;
            cell.title = `Bucket ${i}: ${d} entries`;
        }

        // Top IPs
        const topList = document.getElementById('hash-top-ips');
        const topIPs = stats.topIPs;
        const fragment = document.createDocumentFragment();
        for (const entry of topIPs) {
            const row = document.createElement('div');
            row.className = `top-ip-row ${KNOWN_MALICIOUS_IPS.includes(entry.key) ? 'malicious-ip' : ''}`;
            row.innerHTML = `
                <span class="ip-addr">${KNOWN_MALICIOUS_IPS.includes(entry.key) ? '🔴 ' : ''}${entry.key}</span>
                <span class="ip-count">${entry.value}</span>
                <div class="ip-bar"><div class="ip-bar-fill" style="width:${Math.min(100, (entry.value / Math.max(1, topIPs[0]?.value)) * 100)}%"></div></div>
            `;
            fragment.appendChild(row);
        }
        topList.innerHTML = '';
        topList.appendChild(fragment);
    }

    // ── BST Visualization (Canvas) ───────────────────────────

    _initBSTCanvas() {
        this.bstCanvas = document.getElementById('bst-canvas');
        this.bstCtx = this.bstCanvas.getContext('2d');
        this._resizeBSTCanvas();
        window.addEventListener('resize', () => this._resizeBSTCanvas());
    }

    _resizeBSTCanvas() {
        const parent = this.bstCanvas.parentElement;
        this.bstCanvas.width = parent.clientWidth - 20;
        this.bstCanvas.height = 220;
    }

    _updateBSTViz() {
        const ctx = this.bstCtx;
        const w = this.bstCanvas.width;
        const h = this.bstCanvas.height;
        ctx.clearRect(0, 0, w, h);

        const stats = this.analyzer.bst.getStats();
        document.getElementById('bst-stats').innerHTML =
            `<span>Nodes: <b>${stats.nodeCount}</b></span>` +
            `<span>Height: <b>${stats.treeHeight}</b></span>` +
            `<span>Max Sev: <b>${stats.maxSeverity}</b></span>` +
            `<span>Insertions: <b>${stats.totalInsertions}</b></span>`;

        const tree = this.analyzer.bst.getTreeData();
        if (!tree) return;

        this._drawNode(ctx, tree, w / 2, 25, w / 4, 0);

        // Severity distribution mini bar chart
        const dist = this.analyzer.bst.getSeverityDistribution();
        const barW = (w - 40) / 10;
        const maxBin = Math.max(1, ...dist);
        const barAreaTop = h - 50;
        const barMaxH = 40;

        ctx.fillStyle = 'rgba(0,240,255,0.15)';
        ctx.fillRect(10, barAreaTop - barMaxH - 5, w - 20, barMaxH + 25);

        for (let i = 0; i < 10; i++) {
            const bh = (dist[i] / maxBin) * barMaxH;
            const x = 20 + i * barW;

            // Gradient color based on severity range
            const hue = 180 - (i * 18); // cyan → red
            ctx.fillStyle = `hsl(${hue}, 100%, 55%)`;
            ctx.fillRect(x, barAreaTop - bh, barW - 4, bh);

            // Label
            ctx.fillStyle = '#8892b0';
            ctx.font = '9px Inter';
            ctx.textAlign = 'center';
            ctx.fillText(`${i * 10}`, x + barW / 2 - 2, barAreaTop + 12);
        }
    }

    _drawNode(ctx, node, x, y, spread, depth) {
        if (!node || depth > 5) return;

        const radius = 14;
        const vGap = 35;

        // Draw edges first
        if (node.left) {
            ctx.beginPath();
            ctx.strokeStyle = 'rgba(0,240,255,0.3)';
            ctx.lineWidth = 1;
            ctx.moveTo(x, y + radius);
            ctx.lineTo(x - spread, y + vGap);
            ctx.stroke();
            this._drawNode(ctx, node.left, x - spread, y + vGap, spread / 2, depth + 1);
        }
        if (node.right) {
            ctx.beginPath();
            ctx.strokeStyle = 'rgba(0,240,255,0.3)';
            ctx.lineWidth = 1;
            ctx.moveTo(x, y + radius);
            ctx.lineTo(x + spread, y + vGap);
            ctx.stroke();
            this._drawNode(ctx, node.right, x + spread, y + vGap, spread / 2, depth + 1);
        }

        // Node circle
        const hue = 180 - (node.severity * 1.8);
        ctx.beginPath();
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${hue}, 100%, 50%, 0.2)`;
        ctx.fill();
        ctx.strokeStyle = `hsl(${hue}, 100%, 55%)`;
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Severity text
        ctx.fillStyle = '#e0e6ff';
        ctx.font = 'bold 10px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(node.severity, x, y);
    }

    // ── Stack Visualization ──────────────────────────────────

    _updateStackViz() {
        const stats = this.analyzer.stack.getStats();
        document.getElementById('stack-stats').innerHTML =
            `<span>Depth: <b>${stats.depth}</b></span>` +
            `<span>Max: <b>${stats.maxSize}</b></span>` +
            `<span>Total Pushed: <b>${stats.totalPushed}</b></span>`;

        const items = this.analyzer.stack.getItems(15);
        const container = document.getElementById('stack-items');
        const fragment = document.createDocumentFragment();

        for (let i = 0; i < items.length; i++) {
            const ev = items[i];
            const el = document.createElement('div');
            el.className = `stack-item severity-${this._sevClass(ev.severity)} ${i === 0 ? 'stack-top' : ''}`;
            el.innerHTML = `
                <span class="stack-icon">${ev.icon}</span>
                <span class="stack-type">${ev.type}</span>
                <span class="stack-sev">${ev.severity}</span>
                <span class="stack-ip">${ev.srcIP}</span>
            `;
            fragment.appendChild(el);
        }

        container.innerHTML = '';
        if (items.length > 0) {
            const topLabel = document.createElement('div');
            topLabel.className = 'stack-label';
            topLabel.textContent = '↑ TOP OF STACK';
            fragment.prepend(topLabel);
        }
        container.appendChild(fragment);
    }

    // ── Charts ───────────────────────────────────────────────

    _initCharts() {
        // Timeline chart
        const tlCtx = document.getElementById('timeline-chart').getContext('2d');
        this.timelineChart = new Chart(tlCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Threats',
                        data: [],
                        borderColor: '#ff00aa',
                        backgroundColor: 'rgba(255,0,170,0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                    {
                        label: 'Logs Processed',
                        data: [],
                        borderColor: '#00f0ff',
                        backgroundColor: 'rgba(0,240,255,0.05)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 200 },
                plugins: {
                    legend: { labels: { color: '#8892b0', font: { family: 'Inter', size: 11 } } },
                },
                scales: {
                    x: { display: false },
                    y: {
                        grid: { color: 'rgba(42,47,90,0.5)' },
                        ticks: { color: '#8892b0', font: { family: 'Inter', size: 10 } },
                    },
                },
            },
        });

        // Attack-type doughnut
        const atCtx = document.getElementById('attack-chart').getContext('2d');
        this.attackChart = new Chart(atCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#ff00aa', '#00f0ff', '#00ff88', '#ff6b35',
                        '#a855f7', '#facc15', '#ef4444',
                    ],
                    borderColor: '#141830',
                    borderWidth: 2,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 300 },
                cutout: '60%',
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#8892b0', font: { family: 'Inter', size: 11 }, padding: 12 },
                    },
                },
            },
        });
    }

    _updateCharts(stats) {
        // Timeline
        const tl = stats.timeline;
        const labels = tl.map((_, i) => i);
        this.timelineChart.data.labels = labels;
        this.timelineChart.data.datasets[0].data = tl.map(t => t.threats);
        this.timelineChart.data.datasets[1].data = tl.map(t => t.logs);
        this.timelineChart.update('none');

        // Attack types
        const atk = stats.attackTypeCounts;
        const keys = Object.keys(atk);
        if (keys.length > 0) {
            this.attackChart.data.labels = keys.map(k => k.replace(/_/g, ' '));
            this.attackChart.data.datasets[0].data = keys.map(k => atk[k]);
            this.attackChart.update('none');
        }
    }

    _clearCharts() {
        this.timelineChart.data.labels = [];
        this.timelineChart.data.datasets[0].data = [];
        this.timelineChart.data.datasets[1].data = [];
        this.timelineChart.update();
        this.attackChart.data.labels = [];
        this.attackChart.data.datasets[0].data = [];
        this.attackChart.update();
    }

    // ── Helpers ───────────────────────────────────────────────

    _sevClass(sev) {
        if (sev >= 80) return 'critical';
        if (sev >= 60) return 'high';
        if (sev >= 40) return 'medium';
        if (sev >= 20) return 'low';
        return 'info';
    }

    _fmtTime(ts) {
        const d = new Date(ts);
        return d.toLocaleTimeString('en-GB', { hour12: false }) + '.' +
            String(d.getMilliseconds()).padStart(3, '0');
    }

    _setText(id, text) {
        const el = document.getElementById(id);
        if (el) el.textContent = text;
    }

    _updateClock() {
        const el = document.getElementById('clock');
        if (el) el.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
    }
}

// ── Boot ─────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const dashboard = new Dashboard();
    dashboard.init();
});
