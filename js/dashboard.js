/* ============================================================
   dashboard.js — CyberShield-AI
   100% client-side simulation engine.
   All data structures run in the browser; no server needed.
   ============================================================ */

class Dashboard {
    constructor() {
        this.isRunning   = false;
        this.speed       = 5;         // logs per tick (0-20)
        this.loop        = null;

        // Engine
        this.generator = new LogGenerator();
        this.analyzer  = new ThreatAnalyzer();

        // DOM refs
        this.logFeed   = document.getElementById('log-feed');
        this.alertFeed = document.getElementById('alert-feed');
        this.bstCanvas = document.getElementById('bst-canvas');

        // Chart data
        this.timelineData    = {
            labels:   [],
            datasets: [{ label: 'Threats', data: [], borderColor: '#ff0055',
                         backgroundColor: 'rgba(255,0,85,0.1)', fill: true, tension: 0.4 }]
        };
        this.attackDistData  = {
            labels: ['Brute Force','DDoS','PrivEsc','Port Scan','Exfil'],
            datasets: [{ data: [0,0,0,0,0],
                         backgroundColor: ['#00f0ff','#ff0055','#b500ff','#ffaa00','#00ffaa'] }]
        };

        this._initCharts();
        this._bindControls();
        this._bindFileUpload();

        // Auto-start
        this.start();
    }

    // ── Charts ──────────────────────────────────────────────

    _initCharts() {
        const ctxT = document.getElementById('timeline-chart').getContext('2d');
        this.timelineChart = new Chart(ctxT, {
            type: 'line', data: this.timelineData,
            options: {
                responsive: true, maintainAspectRatio: false,
                animation: false,
                scales: {
                    x: { display: false },
                    y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } }
                },
                plugins: { legend: { display: false } }
            }
        });

        const ctxA = document.getElementById('attack-dist-chart').getContext('2d');
        this.attackChart = new Chart(ctxA, {
            type: 'doughnut', data: this.attackDistData,
            options: {
                responsive: true, maintainAspectRatio: false,
                animation: false,
                plugins: { legend: { position: 'right', labels: { color: '#8a8aa0' } } },
                borderWidth: 0
            }
        });
    }

    // ── Controls ─────────────────────────────────────────────

    _bindControls() {
        const btnStart   = document.getElementById('btn-start');
        const btnStop    = document.getElementById('btn-stop');
        const btnReset   = document.getElementById('btn-reset');
        const btnTheme   = document.getElementById('btn-theme');
        const speedSlider = document.getElementById('speed-slider');

        if (btnStart)  btnStart.addEventListener('click',  () => this.start());
        if (btnStop)   btnStop.addEventListener('click',   () => this.stop());
        if (btnReset)  btnReset.addEventListener('click',  () => this._reset());

        if (btnTheme) btnTheme.addEventListener('click', () => {
            document.body.classList.toggle('light-mode');
            const isLight = document.body.classList.contains('light-mode');
            btnTheme.innerHTML = isLight ? '🌙 Dark Mode' : '☀️ Light Mode';
            this.timelineChart && this.timelineChart.update();
            this.attackChart   && this.attackChart.update();
        });

        if (speedSlider) speedSlider.addEventListener('input', e => {
            this.speed = parseInt(e.target.value, 10);
            document.getElementById('speed-value').textContent = this.speed;
        });

        // Live clock
        setInterval(() => {
            const el = document.getElementById('clock');
            if (el) el.textContent = new Date().toLocaleTimeString();
        }, 1000);
    }

    // ── Simulation Controls ───────────────────────────────────

    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        this._setStatus('RUNNING', true);
        this.loop = setInterval(() => this._tick(), 500);
    }

    stop() {
        this.isRunning = false;
        this._setStatus('PAUSED', false);
        clearInterval(this.loop);
        this.loop = null;
    }

    _reset() {
        this.stop();

        // Re-create engine
        this.generator = new LogGenerator();
        this.analyzer  = new ThreatAnalyzer();

        // Clear UI
        this.logFeed.innerHTML   = '';
        this.alertFeed.innerHTML = '';
        document.getElementById('stat-processed').textContent  = '0';
        document.getElementById('stat-threats').textContent    = '0';
        document.getElementById('queue-total').textContent     = '0';
        document.getElementById('queue-util').textContent      = '0.0%';
        document.getElementById('queue-bar').style.width       = '0%';
        document.getElementById('queue-viz-items').innerHTML   = '';
        document.getElementById('hash-top-ips').innerHTML      = '';
        document.getElementById('stack-items').innerHTML       = '';

        this.attackDistData.datasets[0].data = [0,0,0,0,0];
        this.attackChart.update();
        this.timelineData.labels = [];
        this.timelineData.datasets[0].data = [];
        this.timelineChart.update();
        this._setStatus('READY', false);
    }

    _setStatus(text, active) {
        const st = document.getElementById('status-text');
        const sd = document.getElementById('status-indicator');
        const bs = document.getElementById('btn-start');
        const bp = document.getElementById('btn-stop');
        if (st) st.textContent = text;
        if (sd) { active ? sd.classList.add('active') : sd.classList.remove('active'); }
        if (bs) { active ? bs.classList.add('active') : bs.classList.remove('active'); }
        if (bp) bp.disabled = !active;
    }

    // ── Core Tick ─────────────────────────────────────────────

    _tick() {
        // Generate & enqueue N events based on current speed
        const count = this.speed > 0 ? Math.max(1, Math.round(this.speed / 2)) : 1;
        const events = this.generator.generateBatch(count);
        this.analyzer.ingest(events);

        // Process the queue
        const newAlerts = this.analyzer.processQueue(20);

        // Render new log lines (most recent batch only)
        const recent = events.slice(-8);
        for (const ev of recent) {
            this._addLogEntry(ev);
        }

        // Render alerts
        for (const al of newAlerts) {
            this._addAlertEntry(al);
            this._updateAttackChart(al.attackType);
        }

        // Stats
        const stats = this.analyzer.getStats();
        document.getElementById('stat-processed').textContent  = stats.totalProcessed;
        document.getElementById('stat-threats').textContent    = stats.totalThreats;
        document.getElementById('queue-total').textContent     = stats.queueStats.totalEnqueued;

        const util = parseFloat(stats.queueStats.utilization);
        document.getElementById('queue-util').textContent      = util.toFixed(1) + '%';
        document.getElementById('queue-bar').style.width       = Math.min(util, 100) + '%';

        // Data-structure visualizers
        this._renderQueueItems(this.analyzer.queue);
        this._renderHashTableItems(stats.topIPs);
        this._renderStackItems(this.analyzer.stack);
        this._drawBSTVisualizer(this.analyzer.bst);

        // Timeline chart
        const time = new Date().toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' });
        this.timelineData.labels.push(time);
        this.timelineData.datasets[0].data.push(newAlerts.length);
        if (this.timelineData.labels.length > 30) {
            this.timelineData.labels.shift();
            this.timelineData.datasets[0].data.shift();
        }
        this.timelineChart.update('none');
    }

    // ── Data-Structure Renderers ──────────────────────────────

    _renderQueueItems(queue) {
        const container = document.getElementById('queue-viz-items');
        const statsEl   = document.getElementById('queue-stats');
        if (!container) return;

        const s = queue.getStats();
        if (statsEl) statsEl.innerHTML =
            `<span>Queue: <b>${s.size}</b>/${s.capacity} &nbsp;|&nbsp; Total enqueued: <b>${s.totalEnqueued}</b></span>`;

        const items = queue.getItems(10);
        if (!items || items.length === 0) {
            container.innerHTML = '<div style="color:var(--text-muted);font-size:0.8rem;padding:10px;">Queue empty — start simulation</div>';
            return;
        }

        let html = '';
        items.forEach((item, idx) => {
            const color = item.severity > 70 ? 'var(--red)' : item.severity > 40 ? 'var(--orange)' : 'var(--cyan)';
            const ip    = item.srcIP || item.ip || '—';
            const act   = item.type  || item.action || '—';
            const sev   = item.severity || 0;
            html += `
                <div style="display:flex;justify-content:space-between;align-items:center;
                            background:rgba(0,240,255,0.06);border-left:3px solid ${color};
                            padding:6px 10px;margin-bottom:6px;border-radius:var(--radius-sm);
                            font-family:'JetBrains Mono',monospace;font-size:0.8rem;">
                    <div>
                        <span style="color:var(--text-muted);font-size:0.72rem;">#${idx+1}</span>
                        <span style="color:var(--text-primary);margin-left:4px;">${ip}</span>
                    </div>
                    <div>
                        <span style="color:var(--magenta);margin-right:6px;">${act}</span>
                        <span style="color:${color};font-weight:600;">[S:${sev}]</span>
                    </div>
                </div>`;
        });
        container.innerHTML = html;
    }

    _renderHashTableItems(topIPs) {
        const container = document.getElementById('hash-top-ips');
        const statsEl   = document.getElementById('hash-stats');
        if (!container) return;

        const s = this.analyzer.ipTable.getStats();
        if (statsEl) statsEl.innerHTML =
            `<span>IPs tracked: <b>${s.entries}</b> &nbsp;|&nbsp; Load factor: <b>${s.loadFactor}</b> &nbsp;|&nbsp; Collisions: <b>${s.collisions}</b></span>`;

        if (!topIPs || topIPs.length === 0) {
            container.innerHTML = '<div style="color:var(--text-muted);font-size:0.8rem;padding:10px;">No IP data yet</div>';
            return;
        }

        const maxCount = Math.max(...topIPs.map(i => i.value || i.count || 0), 1);
        let html = '';
        topIPs.forEach(item => {
            const ip    = item.key   || item.ip    || '—';
            const count = item.value || item.count || 0;
            const pct   = Math.min((count / maxCount) * 100, 100);
            const isMal = (typeof KNOWN_MALICIOUS_IPS !== 'undefined') && KNOWN_MALICIOUS_IPS.includes(ip);
            html += `
                <div style="margin-bottom:8px;">
                    <div style="display:flex;justify-content:space-between;font-size:0.8rem;margin-bottom:2px;">
                        <span style="color:${isMal ? 'var(--red)' : 'var(--green)'};font-weight:500;">
                            ${isMal ? '⚠️ ' : ''}${ip}</span>
                        <span style="color:var(--text-secondary);">${count} hits</span>
                    </div>
                    <div style="height:5px;background:rgba(0,255,136,0.1);border-radius:3px;overflow:hidden;">
                        <div style="width:${pct}%;height:100%;background:${isMal ? 'var(--red)' : 'var(--green)'};border-radius:3px;transition:width 0.3s;"></div>
                    </div>
                </div>`;
        });
        container.innerHTML = html;
    }

    _renderStackItems(stack) {
        const container = document.getElementById('stack-items');
        const statsEl   = document.getElementById('stack-stats');
        if (!container) return;

        const s = stack.getStats();
        if (statsEl) statsEl.innerHTML =
            `<span>Depth (LIFO): <b>${s.depth}</b>/${s.maxSize} &nbsp;|&nbsp; Total pushed: <b>${s.totalPushed}</b></span>`;

        const items = stack.getItems(8);
        if (!items || items.length === 0) {
            container.innerHTML = '<div style="color:var(--text-muted);font-size:0.8rem;padding:10px;">Stack empty</div>';
            return;
        }

        let html = '';
        items.forEach((item, idx) => {
            const isTop  = idx === 0;
            const ip     = item.srcIP || item.ip   || '—';
            const act    = item.type  || item.action || '—';
            html += `
                <div style="display:flex;justify-content:space-between;align-items:center;
                            background:${isTop ? 'rgba(255,107,53,0.12)' : 'rgba(0,0,0,0.2)'};
                            border:1px solid ${isTop ? 'var(--orange)' : 'var(--border)'};
                            padding:6px 10px;margin-bottom:6px;border-radius:var(--radius-sm);
                            font-family:'JetBrains Mono',monospace;font-size:0.8rem;">
                    <div>
                        <span style="color:${isTop ? 'var(--orange)' : 'var(--text-muted)'};font-weight:600;font-size:0.75rem;">
                            ${isTop ? 'TOP ➔' : `[${idx}]`}</span>
                        <span style="color:var(--text-primary);margin-left:6px;">${ip}</span>
                    </div>
                    <div><span style="color:var(--magenta);">${act}</span></div>
                </div>`;
        });
        container.innerHTML = html;
    }

    _drawBSTVisualizer(bst) {
        if (!this.bstCanvas) return;
        const canvas  = this.bstCanvas;
        const ctx     = canvas.getContext('2d');
        const W       = canvas.offsetWidth  || 340;
        const H       = 150;
        canvas.width  = W;
        canvas.height = H;
        ctx.clearRect(0, 0, W, H);

        const isLight = document.body.classList.contains('light-mode');
        const nodeCol = isLight ? '#9333ea' : '#00f0ff';
        const lineCol = isLight ? 'rgba(0,0,0,0.15)' : 'rgba(168,85,247,0.4)';
        const textCol = isLight ? '#1e293b' : '#a855f7';

        const treeData = bst.getTreeData();
        if (!treeData) {
            ctx.fillStyle = textCol;
            ctx.font = '11px "JetBrains Mono", monospace';
            ctx.fillText('AVL BST — Insert events to populate', 10, 20);
            return;
        }

        const stats = bst.getStats();
        ctx.fillStyle = textCol;
        ctx.font = '11px "JetBrains Mono", monospace';
        ctx.fillText(`AVL BST · Nodes:${stats.nodeCount} Height:${stats.treeHeight} MaxSev:${stats.maxSeverity}`, 8, 14);

        // BFS layout
        const positions = new Map();
        const queue     = [{ node: treeData, x: W / 2, y: 38, spread: W / 3 }];
        const edges     = [];

        while (queue.length) {
            const { node, x, y, spread } = queue.shift();
            if (!node) continue;
            positions.set(node, { x, y });
            if (node.left) {
                const cx = x - spread, cy = y + 32;
                edges.push({ x1: x, y1: y, x2: cx, y2: cy });
                queue.push({ node: node.left,  x: cx, y: cy, spread: spread / 2 });
            }
            if (node.right) {
                const cx = x + spread, cy = y + 32;
                edges.push({ x1: x, y1: y, x2: cx, y2: cy });
                queue.push({ node: node.right, x: cx, y: cy, spread: spread / 2 });
            }
        }

        // Draw edges
        ctx.strokeStyle = lineCol;
        ctx.lineWidth   = 1.5;
        for (const e of edges) {
            ctx.beginPath();
            ctx.moveTo(e.x1, e.y1);
            ctx.lineTo(e.x2, e.y2);
            ctx.stroke();
        }

        // Draw nodes
        for (const [node, { x, y }] of positions) {
            const sev   = node.severity || 0;
            const color = sev > 70 ? '#ff3355' : sev > 40 ? '#ffaa00' : nodeCol;
            ctx.beginPath();
            ctx.arc(x, y, 7, 0, 2 * Math.PI);
            ctx.fillStyle = color;
            ctx.fill();

            ctx.fillStyle = '#ffffff';
            ctx.font      = '8px "JetBrains Mono", monospace';
            ctx.textAlign = 'center';
            ctx.fillText(sev, x, y + 3);
        }
        ctx.textAlign = 'left';
    }

    // ── Log & Alert Renderers ─────────────────────────────────

    _addLogEntry(ev) {
        if (!this.logFeed) return;
        const div   = document.createElement('div');
        div.className = 'log-entry';
        const sev   = ev.severity || 0;
        const color = sev > 70 ? 'var(--red)' : sev > 40 ? 'var(--orange)' : 'var(--cyan)';
        const time  = new Date(ev.timestamp || Date.now()).toLocaleTimeString();
        const icon  = ev.icon || '📋';
        const ip    = ev.srcIP || ev.ip   || '—';
        const act   = ev.type  || ev.action || '—';
        const port  = ev.port  || '—';

        div.innerHTML = `
            <span style="color:var(--text-muted)">[${time}]</span>
            <span style="color:${color};width:32px;display:inline-block;font-weight:600;">[S:${sev}]</span>
            <span>${icon}</span>
            <span style="color:var(--text-primary);width:115px;display:inline-block;">${ip}</span>
            <span style="color:var(--magenta);width:180px;display:inline-block;font-weight:500;">${act}</span>
            <span style="color:var(--text-secondary)">:${port}</span>
        `;
        this.logFeed.appendChild(div);
        if (this.logFeed.childNodes.length > 80) this.logFeed.removeChild(this.logFeed.firstChild);
        this.logFeed.scrollTop = this.logFeed.scrollHeight;
    }

    _addAlertEntry(al) {
        if (!this.alertFeed) return;
        const div   = document.createElement('div');
        div.className = 'alert-entry';
        div.style.cssText = 'border-left:4px solid var(--red);padding:8px 12px;margin-bottom:8px;background:rgba(255,51,85,0.08);border-radius:var(--radius-sm);';
        const time  = new Date(al.timestamp || Date.now()).toLocaleTimeString();
        const icon  = al.icon || '🚨';
        const type  = (al.attackType || al.type || 'THREAT').replace(/_/g, ' ');

        div.innerHTML = `
            <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                <strong style="color:var(--red);font-size:0.95rem;">${icon} ${type}</strong>
                <span style="color:var(--text-muted);font-size:0.8rem;">${time}</span>
            </div>
            <div style="color:var(--text-primary);font-size:0.85rem;">${al.message || ''}</div>
            <div style="color:var(--text-secondary);font-size:0.78rem;font-family:'JetBrains Mono',monospace;margin-top:2px;">
                IP: ${al.srcIP || '—'}  |  User: ${al.user || '—'}  |  Level: ${(al.level || 'high').toUpperCase()}
            </div>
        `;
        this.alertFeed.appendChild(div);
        if (this.alertFeed.childNodes.length > 40) this.alertFeed.removeChild(this.alertFeed.firstChild);
        this.alertFeed.scrollTop = this.alertFeed.scrollHeight;
    }

    _updateAttackChart(attackType) {
        const t = (attackType || '').toUpperCase();
        let idx = -1;
        if (t.includes('BRUTE'))           idx = 0;
        else if (t.includes('DDOS'))       idx = 1;
        else if (t.includes('PRIVIL') || t.includes('ESCALAT')) idx = 2;
        else if (t.includes('PORT'))       idx = 3;
        else if (t.includes('EXFIL') || t.includes('DATA'))     idx = 4;
        if (idx >= 0) {
            this.attackDistData.datasets[0].data[idx]++;
            this.attackChart.update('none');
        }
    }

    // ── File Upload & Ingestion ───────────────────────────────

    _bindFileUpload() {
        const dropzone   = document.getElementById('dropzone');
        const fileInput  = document.getElementById('file-input');
        const textarea   = document.getElementById('custom-log-text');
        const btnAnalyze = document.getElementById('btn-analyze-file');
        const btnClear   = document.getElementById('btn-clear-file');
        const fileInfo   = document.getElementById('file-info-text');

        if (dropzone && fileInput) {
            dropzone.addEventListener('click', () => fileInput.click());
            dropzone.addEventListener('dragover', e => {
                e.preventDefault();
                dropzone.style.borderColor = 'var(--cyan)';
                dropzone.style.background  = 'rgba(0,240,255,0.08)';
            });
            dropzone.addEventListener('dragleave', () => {
                dropzone.style.borderColor = 'var(--border)';
                dropzone.style.background  = 'rgba(0,0,0,0.15)';
            });
            dropzone.addEventListener('drop', e => {
                e.preventDefault();
                dropzone.style.borderColor = 'var(--border)';
                dropzone.style.background  = 'rgba(0,0,0,0.15)';
                if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                    this._handleFiles(e.dataTransfer.files);
                }
            });
            fileInput.addEventListener('change', e => {
                if (e.target.files && e.target.files.length > 0) {
                    this._handleFiles(e.target.files);
                }
            });
        }

        if (textarea) {
            textarea.addEventListener('input', () => {
                const text   = textarea.value.trim();
                const parsed = text ? this._parseRawLogText(text) : [];
                document.getElementById('parsed-count-tag').textContent = `${parsed.length} events parsed`;
                if (text) {
                    fileInfo.innerHTML = `<span style="color:var(--cyan);">📄 Ready (${parsed.length} events parsed)</span>`;
                } else {
                    fileInfo.textContent = 'No file selected. Drop a .txt / .log / .pdf or paste logs above.';
                }
            });
        }

        if (btnAnalyze) {
            btnAnalyze.addEventListener('click', () => {
                const text = textarea ? textarea.value.trim() : '';
                if (!text) { alert('Please select a file or paste raw logs first.'); return; }

                const parsedEvents = this._parseRawLogText(text);
                if (parsedEvents.length === 0) { alert('No valid log events could be parsed.'); return; }

                btnAnalyze.disabled    = true;
                btnAnalyze.textContent = '⏳ Analyzing...';

                // Feed into engine directly (client-side)
                this.analyzer.ingest(parsedEvents);
                const newAlerts = this.analyzer.processQueue(parsedEvents.length);

                for (const ev of parsedEvents.slice(-30)) this._addLogEntry(ev);
                for (const al of newAlerts)               { this._addAlertEntry(al); this._updateAttackChart(al.attackType); }

                const stats = this.analyzer.getStats();
                document.getElementById('stat-processed').textContent  = stats.totalProcessed;
                document.getElementById('stat-threats').textContent    = stats.totalThreats;

                // Refresh visualizers
                this._renderQueueItems(this.analyzer.queue);
                this._renderHashTableItems(stats.topIPs);
                this._renderStackItems(this.analyzer.stack);
                this._drawBSTVisualizer(this.analyzer.bst);

                fileInfo.innerHTML = `<span style="color:var(--green);">✅ Analyzed ${parsedEvents.length} events — Detected ${newAlerts.length} threats!</span>`;
                btnAnalyze.disabled    = false;
                btnAnalyze.textContent = '⚡ Analyze with Engine';
            });
        }

        if (btnClear) {
            btnClear.addEventListener('click', () => {
                if (textarea)  textarea.value  = '';
                if (fileInput) fileInput.value  = '';
                document.getElementById('parsed-count-tag').textContent = '0 events parsed';
                if (fileInfo) fileInfo.textContent = 'No file selected. Drop a .txt / .log / .pdf or paste logs above.';
            });
        }

        // ── Preset buttons ─────────────────────────────────────
        const presetBrute   = document.getElementById('preset-brute');
        const presetDdos    = document.getElementById('preset-ddos');
        const presetPrivesc = document.getElementById('preset-privesc');

        if (presetBrute) {
            presetBrute.addEventListener('click', () => {
                let text = '';
                for (let i = 0; i < 22; i++) {
                    text += `2026-09-27 12:00:${i.toString().padStart(2,'0')} [ERROR] 198.51.100.44 LOGIN_ATTEMPT FAILED port 22 (Severity 5)\n`;
                }
                if (textarea) { textarea.value = text; textarea.dispatchEvent(new Event('input')); }
            });
        }

        if (presetDdos) {
            presetDdos.addEventListener('click', () => {
                let text = '';
                for (let i = 0; i < 35; i++) {
                    text += `2026-09-27 12:05:${(i % 60).toString().padStart(2,'0')} [CRITICAL] 203.0.113.88 DATA_READ SUCCESS port 80 (Severity 8)\n`;
                }
                if (textarea) { textarea.value = text; textarea.dispatchEvent(new Event('input')); }
            });
        }

        if (presetPrivesc) {
            presetPrivesc.addEventListener('click', () => {
                let text = `2026-09-27 12:10:01 [INFO] 10.0.4.15 LOGIN_ATTEMPT SUCCESS port 22 (Severity 2)\n`;
                text += `2026-09-27 12:10:02 [CRITICAL] 10.0.4.15 PRIVILEGE_ESCALATION SUCCESS port 22 (Severity 10)\n`;
                text += `2026-09-27 12:10:05 [CRITICAL] 10.0.4.15 DATA_EXPORT SUCCESS port 443 (Severity 10)\n`;
                for (let i = 0; i < 12; i++) {
                    text += `2026-09-27 12:10:${(i+6).toString().padStart(2,'0')} [WARN] 10.0.4.15 PORT_SCAN BLOCKED port ${100+i*10} (Severity 6)\n`;
                }
                if (textarea) { textarea.value = text; textarea.dispatchEvent(new Event('input')); }
            });
        }
    }

    // ── File Reading ──────────────────────────────────────────

    async _handleFiles(files) {
        const fileInfo = document.getElementById('file-info-text');
        const textarea = document.getElementById('custom-log-text');
        let combined   = '';

        for (const file of files) {
            if (fileInfo) fileInfo.innerHTML = `<span style="color:var(--yellow);">⏳ Reading ${file.name}...</span>`;
            if (file.name.toLowerCase().endsWith('.pdf')) {
                const txt = await this._readPdfFile(file);
                combined += `\n--- [PDF: ${file.name}] ---\n` + txt;
            } else {
                const txt = await this._readTextFile(file);
                combined += `\n--- [LOG: ${file.name}] ---\n` + txt;
            }
        }

        if (textarea) {
            textarea.value = combined.trim();
            textarea.dispatchEvent(new Event('input'));
        }
    }

    _readTextFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload  = e => resolve(e.target.result);
            reader.onerror = e => reject(e);
            reader.readAsText(file);
        });
    }

    async _readPdfFile(file) {
        if (!window.pdfjsLib) return '[PDF.js not loaded]';
        try {
            const buf = await file.arrayBuffer();
            const pdf = await pdfjsLib.getDocument({ data: buf }).promise;
            let text  = '';
            for (let p = 1; p <= pdf.numPages; p++) {
                const page = await pdf.getPage(p);
                const tok  = await page.getTextContent();
                text += tok.items.map(i => i.str).join(' ') + '\n';
            }
            return text;
        } catch (err) {
            return `[PDF Error: ${err.message}]`;
        }
    }

    // ── Intelligent Log Line Parser ───────────────────────────

    _parseRawLogText(rawText) {
        const lines  = rawText.split('\n');
        const events = [];
        const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;

        for (const line of lines) {
            const l = line.trim();
            if (!l || l.startsWith('---')) continue;

            const ipMatch = l.match(ipRegex);
            const ip      = ipMatch ? ipMatch[0] : '192.168.1.50';

            const uL = l.toUpperCase();
            let type = 'FILE_ACCESS', severity = 30;

            if (uL.includes('LOGIN') && uL.includes('FAIL'))       { type = 'LOGIN_FAILED';         severity = 40; }
            else if (uL.includes('LOGIN') && uL.includes('SUCCESS')){ type = 'LOGIN_SUCCESS';        severity = 10; }
            else if (uL.includes('PRIVILEGE') || uL.includes('SUDO')){ type = 'PRIVILEGE_ESCALATION'; severity = 85; }
            else if (uL.includes('PORT_SCAN') || uL.includes('SCAN')){ type = 'PORT_SCAN';           severity = 60; }
            else if (uL.includes('EXPORT') || uL.includes('EXFIL')) { type = 'DATA_EXFILTRATION';    severity = 90; }
            else if (uL.includes('MALWARE'))                        { type = 'MALWARE_DETECTED';     severity = 95; }
            else if (uL.includes('DDOS') || uL.includes('FLOOD'))   { type = 'DDOS_TRAFFIC';         severity = 75; }
            else if (uL.includes('FIREWALL') || uL.includes('BLOCK')){ type = 'FIREWALL_BLOCK';      severity = 45; }

            if (uL.includes('CRITICAL') || uL.includes('FATAL'))   severity = Math.max(severity, 85);
            else if (uL.includes('ERROR'))                          severity = Math.max(severity, 65);
            else if (uL.includes('WARN'))                           severity = Math.max(severity, 50);

            const sevMatch = l.match(/severity\s*[:\(]?\s*(\d+)/i);
            if (sevMatch) severity = Math.min(parseInt(sevMatch[1], 10) * 10, 100);

            const portMatch = l.match(/port\s*:?\s*(\d+)/i);
            const port      = portMatch ? parseInt(portMatch[1], 10) : (type === 'LOGIN_FAILED' ? 22 : 80);

            const isMal     = (typeof KNOWN_MALICIOUS_IPS !== 'undefined') && KNOWN_MALICIOUS_IPS.includes(ip);
            const icons     = { LOGIN_FAILED:'🔐', LOGIN_SUCCESS:'🔓', PORT_SCAN:'🔍',
                                 PRIVILEGE_ESCALATION:'⚡', DATA_EXFILTRATION:'📤',
                                 MALWARE_DETECTED:'🦠', DDOS_TRAFFIC:'🌊', FIREWALL_BLOCK:'🛡️',
                                 FILE_ACCESS:'📄' };

            events.push({
                id: Date.now() + Math.random(),
                timestamp:     Date.now(),
                type, severity, port,
                srcIP:         ip,
                destIP:        '10.0.0.1',
                protocol:      'TCP',
                user:          'parsed_user',
                sessionId:     `PARSE-${Date.now()}`,
                message:       l.slice(0, 100),
                icon:          icons[type] || '📋',
                isMaliciousIP: isMal,
            });
        }
        return events;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new Dashboard();
});
