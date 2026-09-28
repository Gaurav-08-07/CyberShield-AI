class Dashboard {
    constructor() {
        this.isRunning = false;
        this.speed = 5;
        this.logFeed = document.getElementById('log-feed');
        this.alertFeed = document.getElementById('alert-feed');
        this.bstCanvas = document.getElementById('bst-canvas');
        
        this.timelineData = { labels: [], datasets: [{ label: 'Threats', data: [], borderColor: '#ff0055', backgroundColor: 'rgba(255,0,85,0.1)', fill: true, tension: 0.4 }] };
        this.attackDistData = { labels: ['Brute Force', 'DDoS', 'PrivEsc', 'Port Scan', 'Exfil'], datasets: [{ data: [0, 0, 0, 0, 0], backgroundColor: ['#00f0ff', '#ff0055', '#b500ff', '#ffaa00', '#00ffaa'] }] };
        
        this._initCharts();
        this._bindControls();
        this._bindFileUpload();
        
        // Auto start tick loop
        this.start();
    }

    _apiUrl(path) {
        if (window.location.protocol.startsWith('http')) {
            return path;
        }
        return 'http://localhost:8080' + path;
    }

    _initCharts() {
        const ctxTimeline = document.getElementById('timeline-chart').getContext('2d');
        this.timelineChart = new Chart(ctxTimeline, {
            type: 'line', data: this.timelineData,
            options: { responsive: true, maintainAspectRatio: false, scales: { x: { display: false }, y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } } }, plugins: { legend: { display: false } } }
        });

        const ctxAttack = document.getElementById('attack-dist-chart').getContext('2d');
        this.attackChart = new Chart(ctxAttack, {
            type: 'doughnut', data: this.attackDistData,
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#8a8aa0' } } }, borderWidth: 0 }
        });
    }

    _bindControls() {
        const btnStart = document.getElementById('btn-start');
        const btnStop = document.getElementById('btn-stop');
        const btnReset = document.getElementById('btn-reset');
        const btnTheme = document.getElementById('btn-theme');
        const speedSlider = document.getElementById('speed-slider');

        if (btnStart) btnStart.addEventListener('click', () => this.start());
        if (btnStop) btnStop.addEventListener('click', () => this.stop());
        if (btnReset) btnReset.addEventListener('click', () => {
            this.stop();
            fetch(this._apiUrl('/api/reset'));
            this.logFeed.innerHTML = '';
            this.alertFeed.innerHTML = '';
            document.getElementById('stat-processed').textContent = '0';
            document.getElementById('stat-threats').textContent = '0';
            document.getElementById('queue-total').textContent = '0';
            document.getElementById('queue-util').textContent = '0.0%';
            document.getElementById('queue-bar').style.width = '0%';
            this.attackDistData.datasets[0].data = [0, 0, 0, 0, 0];
            this.attackChart.update();
            this.timelineData.labels = [];
            this.timelineData.datasets[0].data = [];
            this.timelineChart.update();
        });

        if (btnTheme) btnTheme.addEventListener('click', () => {
            document.body.classList.toggle('light-mode');
            const isLight = document.body.classList.contains('light-mode');
            btnTheme.innerHTML = isLight ? '🌙 Dark Mode' : '☀️ Light Mode';
            if (this.timelineChart) this.timelineChart.update();
            if (this.attackChart) this.attackChart.update();
        });

        if (speedSlider) speedSlider.addEventListener('input', (e) => {
            this.speed = parseInt(e.target.value, 10);
            document.getElementById('speed-value').textContent = this.speed;
            fetch(this._apiUrl(`/api/speed?val=${this.speed}`));
        });

        // Start clock
        setInterval(() => {
            const clockEl = document.getElementById('clock');
            if (clockEl) clockEl.textContent = new Date().toLocaleTimeString();
        }, 1000);
    }

    _bindFileUpload() {
        const dropzone = document.getElementById('dropzone');
        const fileInput = document.getElementById('file-input');
        const textarea = document.getElementById('custom-log-text');
        const btnAnalyze = document.getElementById('btn-analyze-file');
        const btnClear = document.getElementById('btn-clear-file');
        const fileInfo = document.getElementById('file-info-text');

        if (dropzone && fileInput) {
            dropzone.addEventListener('click', () => fileInput.click());
            dropzone.addEventListener('dragover', (e) => {
                e.preventDefault();
                dropzone.style.borderColor = 'var(--cyan)';
                dropzone.style.background = 'rgba(0,240,255,0.08)';
            });
            dropzone.addEventListener('dragleave', () => {
                dropzone.style.borderColor = 'var(--border)';
                dropzone.style.background = 'rgba(0,0,0,0.15)';
            });
            dropzone.addEventListener('drop', (e) => {
                e.preventDefault();
                dropzone.style.borderColor = 'var(--border)';
                dropzone.style.background = 'rgba(0,0,0,0.15)';
                if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                    this._handleFiles(e.dataTransfer.files);
                }
            });
            fileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files.length > 0) {
                    this._handleFiles(e.target.files);
                }
            });
        }

        if (textarea) {
            textarea.addEventListener('input', () => {
                const text = textarea.value.trim();
                if (text) {
                    const parsed = this._parseRawLogText(text);
                    document.getElementById('parsed-count-tag').textContent = `${parsed.length} events parsed`;
                    fileInfo.innerHTML = `<span style="color: var(--cyan);">📄 Pasted Text Ready (${parsed.length} events parsed)</span>`;
                } else {
                    document.getElementById('parsed-count-tag').textContent = '0 events parsed';
                    fileInfo.textContent = 'No file selected. Drop a .txt / .log / .pdf or paste logs above.';
                }
            });
        }

        if (btnAnalyze) {
            btnAnalyze.addEventListener('click', async () => {
                const text = textarea ? textarea.value.trim() : '';
                if (!text) {
                    alert('Please select a file or paste raw logs first.');
                    return;
                }
                const parsedEvents = this._parseRawLogText(text);
                if (parsedEvents.length === 0) {
                    alert('No valid log events could be parsed from the input.');
                    return;
                }

                btnAnalyze.disabled = true;
                btnAnalyze.textContent = '⏳ Processing in C Engine...';

                try {
                    const res = await fetch(this._apiUrl('/api/ingest'), {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(parsedEvents)
                    });
                    const data = await res.json();
                    
                    if (data.status === 'ok') {
                        fileInfo.innerHTML = `<span style="color: var(--green);">✅ C Engine Analyzed ${data.ingested} Events & Detected ${data.alertsGenerated} Threats!</span>`;
                        this._tick(); // Immediate refresh
                    } else {
                        fileInfo.innerHTML = `<span style="color: var(--red);">❌ Ingestion failed: ${data.message}</span>`;
                    }
                } catch (err) {
                    console.error("Error sending to C backend:", err);
                    fileInfo.innerHTML = `<span style="color: var(--red);">❌ Backend connection error. Ensure C server is running.</span>`;
                } finally {
                    btnAnalyze.disabled = false;
                    btnAnalyze.textContent = '⚡ Analyze with C Engine';
                }
            });
        }

        if (btnClear) {
            btnClear.addEventListener('click', () => {
                if (textarea) textarea.value = '';
                if (fileInput) fileInput.value = '';
                document.getElementById('parsed-count-tag').textContent = '0 events parsed';
                fileInfo.textContent = 'No file selected. Drop a .txt / .log / .pdf or paste logs above.';
            });
        }

        // Preset Buttons
        const presetBrute = document.getElementById('preset-brute');
        const presetDdos = document.getElementById('preset-ddos');
        const presetPrivesc = document.getElementById('preset-privesc');

        if (presetBrute) {
            presetBrute.addEventListener('click', () => {
                let text = '';
                for (let i = 0; i < 22; i++) {
                    text += `2026-09-27 12:00:${i.toString().padStart(2, '0')} [ERROR] 198.51.100.44 LOGIN_ATTEMPT FAILED port 22 (Severity 5)\n`;
                }
                textarea.value = text;
                textarea.dispatchEvent(new Event('input'));
            });
        }

        if (presetDdos) {
            presetDdos.addEventListener('click', () => {
                let text = '';
                for (let i = 0; i < 35; i++) {
                    text += `2026-09-27 12:05:${(i % 60).toString().padStart(2, '0')} [CRITICAL] 203.0.113.88 DATA_READ SUCCESS port 80 (Severity 8)\n`;
                }
                textarea.value = text;
                textarea.dispatchEvent(new Event('input'));
            });
        }

        if (presetPrivesc) {
            presetPrivesc.addEventListener('click', () => {
                let text = `2026-09-27 12:10:01 [INFO] 10.0.4.15 LOGIN_ATTEMPT SUCCESS port 22 (Severity 2)\n`;
                text += `2026-09-27 12:10:02 [CRITICAL] 10.0.4.15 PRIVILEGE_ESCALATION SUCCESS port 22 (Severity 10)\n`;
                text += `2026-09-27 12:10:05 [CRITICAL] 10.0.4.15 DATA_EXPORT SUCCESS port 443 (Severity 10)\n`;
                for (let i = 0; i < 12; i++) {
                    text += `2026-09-27 12:10:${(i + 6).toString().padStart(2, '0')} [WARN] 10.0.4.15 PORT_SCAN BLOCKED port ${100 + i*10} (Severity 6)\n`;
                }
                textarea.value = text;
                textarea.dispatchEvent(new Event('input'));
            });
        }
    }

    async _handleFiles(files) {
        const fileInfo = document.getElementById('file-info-text');
        const textarea = document.getElementById('custom-log-text');
        
        let combinedText = '';
        for (const file of files) {
            fileInfo.innerHTML = `<span style="color: var(--yellow);">⏳ Reading ${file.name}...</span>`;
            if (file.name.toLowerCase().endsWith('.pdf')) {
                const pdfText = await this._readPdfFile(file);
                combinedText += `\n--- [PDF LOG FILE: ${file.name}] ---\n` + pdfText;
            } else {
                const text = await this._readTextFile(file);
                combinedText += `\n--- [LOG FILE: ${file.name}] ---\n` + text;
            }
        }

        if (textarea) {
            textarea.value = combinedText.trim();
            textarea.dispatchEvent(new Event('input'));
        }
    }

    _readTextFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsText(file);
        });
    }

    async _readPdfFile(file) {
        if (!window.pdfjsLib) {
            return "Error: PDF.js library not loaded.";
        }
        try {
            const arrayBuffer = await file.arrayBuffer();
            const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
            let fullText = '';
            
            for (let pageNum = 1; pageNum <= pdf.numPages; pageNum++) {
                const page = await pdf.getPage(pageNum);
                const tokenized = await page.getTextContent();
                const pageText = tokenized.items.map(item => item.str).join(' ');
                fullText += pageText + '\n';
            }
            return fullText;
        } catch (err) {
            console.error("PDF Parsing error:", err);
            return `[PDF Parsing Error: ${err.message}]`;
        }
    }

    // Intelligent Log Line Parser
    _parseRawLogText(rawText) {
        const lines = rawText.split('\n');
        const events = [];

        const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (!line || line.startsWith('---')) continue;

            let ip = '192.168.1.50';
            const ipMatch = line.match(ipRegex);
            if (ipMatch) ip = ipMatch[0];

            let action = 'DATA_READ';
            let status = 'SUCCESS';
            let severity = 3;
            let port = 80;

            const uLine = line.toUpperCase();

            // Action detection
            if (uLine.includes('LOGIN') || uLine.includes('AUTH')) action = 'LOGIN_ATTEMPT';
            else if (uLine.includes('PORT_SCAN') || uLine.includes('SCAN')) action = 'PORT_SCAN';
            else if (uLine.includes('PRIVILEGE') || uLine.includes('SUDO') || uLine.includes('ROOT')) action = 'PRIVILEGE_ESCALATION';
            else if (uLine.includes('EXPORT') || uLine.includes('EXFIL') || uLine.includes('DOWNLOAD')) action = 'DATA_EXPORT';
            else if (uLine.includes('UPLOAD')) action = 'FILE_UPLOAD';
            else if (uLine.includes('READ') || uLine.includes('GET') || uLine.includes('QUERY')) action = 'DATA_READ';

            // Status detection
            if (uLine.includes('FAIL') || uLine.includes('DENIED') || uLine.includes('401') || uLine.includes('403') || uLine.includes('ERROR')) {
                status = 'FAILED';
                severity = 7;
            } else if (uLine.includes('BLOCK') || uLine.includes('REJECT')) {
                status = 'BLOCKED';
                severity = 6;
            } else if (uLine.includes('SUCCESS') || uLine.includes('200')) {
                status = 'SUCCESS';
                severity = 2;
            }

            // Severity override based on keywords
            if (uLine.includes('CRITICAL') || uLine.includes('FATAL') || uLine.includes('EXFIL') || uLine.includes('PRIVILEGE_ESCALATION')) {
                severity = 10;
            } else if (uLine.includes('ERROR') || uLine.includes('EXCEPTION') || uLine.includes('BRUTE')) {
                severity = 8;
            } else if (uLine.includes('WARN')) {
                severity = 5;
            }

            // Port detection
            const portMatch = line.match(/port\s*[:=]?\s*(\d+)/i) || line.match(/:(\d{2,5})\b/);
            if (portMatch) {
                port = parseInt(portMatch[1], 10);
            } else if (action === 'LOGIN_ATTEMPT') port = 22;
            else if (action === 'DATA_READ') port = 80;

            events.push({ ip, action, port, status, severity });
        }

        return events;
    }

    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        const btnStart = document.getElementById('btn-start');
        const btnStop = document.getElementById('btn-stop');
        const statusText = document.getElementById('status-text');
        const statusInd = document.getElementById('status-indicator');

        if (btnStart) {
            btnStart.classList.add('active');
            btnStart.disabled = true;
        }
        if (btnStop) btnStop.disabled = false;
        if (statusText) statusText.textContent = 'RUNNING';
        if (statusInd) statusInd.classList.add('active');

        fetch(this._apiUrl(`/api/speed?val=${this.speed || 5}`));
        if (!this.loop) {
            this.loop = setInterval(() => this._tick(), 500);
        }
    }

    stop() {
        this.isRunning = false;
        const btnStart = document.getElementById('btn-start');
        const btnStop = document.getElementById('btn-stop');
        const statusText = document.getElementById('status-text');
        const statusInd = document.getElementById('status-indicator');

        if (btnStart) {
            btnStart.classList.remove('active');
            btnStart.disabled = false;
        }
        if (btnStop) btnStop.disabled = true;
        if (statusText) statusText.textContent = 'PAUSED';
        if (statusInd) statusInd.classList.remove('active');

        fetch(this._apiUrl(`/api/speed?val=0`));
    }

    async _tick() {
        try {
            const res = await fetch(this._apiUrl('/api/state'));
            const data = await res.json();
            
            // Append logs
            for (const ev of data.logs) {
                this._addLogEntry(ev);
            }
            
            // Append alerts
            for (const al of data.alerts) {
                this._addAlertEntry(al);
                this._updateAttackChart(al.type);
            }
            
            // Update UI Stats
            document.getElementById('stat-processed').textContent = data.stats.processed;
            document.getElementById('stat-threats').textContent = data.stats.threats;
            document.getElementById('queue-total').textContent = data.stats.queueTotal;
            
            const util = (data.stats.queueSize / 500) * 100;
            document.getElementById('queue-util').textContent = util.toFixed(1) + '%';
            document.getElementById('queue-bar').style.width = Math.min(util, 100) + '%';

            // Render DS Visualizer Panels
            if (data.queueItems) this._renderQueueItems(data.queueItems, data.stats.queueSize);
            if (data.topIps) this._renderHashTableItems(data.topIps);
            if (data.stackItems) this._renderStackItems(data.stackItems, data.stats.stackDepth);

            // Update timeline
            if (data.alerts.length > 0) {
                this._updateTimelineChart(data.alerts.length);
            } else if (Math.random() < 0.2) {
                this._updateTimelineChart(0);
            }

            this._drawBSTVisualizer();

        } catch (e) {
            console.error("Backend connection failed", e);
        }
    }

    _renderQueueItems(items, queueSize) {
        const container = document.getElementById('queue-viz-items');
        const statsEl = document.getElementById('queue-stats');
        if (statsEl) statsEl.innerHTML = `<span>Queue Size: <b>${queueSize}</b>/500</span>`;
        if (!container) return;

        if (!items || items.length === 0) {
            container.innerHTML = '<div style="color: var(--text-muted); font-size: 0.8rem; padding: 10px;">Queue empty</div>';
            return;
        }

        let html = '';
        items.forEach((item, idx) => {
            const color = item.severity > 7 ? 'var(--red)' : item.severity > 4 ? 'var(--orange)' : 'var(--cyan)';
            html += `
                <div class="queue-item" style="display: flex; justify-content: space-between; align-items: center; background: rgba(0,240,255,0.06); border-left: 3px solid ${color}; padding: 6px 10px; margin-bottom: 6px; border-radius: var(--radius-sm); font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;">
                    <div>
                        <span style="color: var(--text-muted); font-size: 0.72rem;">#${idx+1}</span>
                        <span style="color: var(--text-primary); margin-left: 4px;">${item.ip}</span>
                    </div>
                    <div>
                        <span style="color: var(--magenta); margin-right: 6px;">${item.action}</span>
                        <span style="color: ${color}; font-weight: 600;">[S:${item.severity}]</span>
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;
    }

    _renderHashTableItems(topIps) {
        const container = document.getElementById('hash-top-ips');
        const statsEl = document.getElementById('hash-stats');
        if (statsEl) statsEl.innerHTML = `<span>Tracked IP Buckets: <b>1024</b> (Top Active IPs)</span>`;
        if (!container) return;

        if (!topIps || topIps.length === 0) {
            container.innerHTML = '<div style="color: var(--text-muted); font-size: 0.8rem; padding: 10px;">No IP buckets populated</div>';
            return;
        }

        const maxCount = Math.max(...topIps.map(i => i.count), 1);
        let html = '';
        topIps.forEach(item => {
            const pct = Math.min((item.count / maxCount) * 100, 100);
            html += `
                <div style="margin-bottom: 8px;">
                    <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 2px;">
                        <span style="color: var(--green); font-weight: 500;">${item.ip}</span>
                        <span style="color: var(--text-secondary);">${item.count} hits</span>
                    </div>
                    <div style="height: 5px; background: rgba(0,255,136,0.1); border-radius: 3px; overflow: hidden;">
                        <div style="width: ${pct}%; height: 100%; background: var(--green); border-radius: 3px;"></div>
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;
    }

    _renderStackItems(items, stackDepth) {
        const container = document.getElementById('stack-items');
        const statsEl = document.getElementById('stack-stats');
        if (statsEl) statsEl.innerHTML = `<span>Stack Depth (LIFO): <b>${stackDepth || items.length}</b></span>`;
        if (!container) return;

        if (!items || items.length === 0) {
            container.innerHTML = '<div style="color: var(--text-muted); font-size: 0.8rem; padding: 10px;">Stack empty</div>';
            return;
        }

        let html = '';
        items.forEach((item, idx) => {
            const isTop = idx === 0;
            html += `
                <div class="stack-item" style="display: flex; justify-content: space-between; align-items: center; background: ${isTop ? 'rgba(255,107,53,0.12)' : 'rgba(0,0,0,0.2)'}; border: 1px solid ${isTop ? 'var(--orange)' : 'var(--border)'}; padding: 6px 10px; margin-bottom: 6px; border-radius: var(--radius-sm); font-family: 'JetBrains Mono', monospace; font-size: 0.8rem;">
                    <div>
                        <span style="color: ${isTop ? 'var(--orange)' : 'var(--text-muted)'}; font-weight: 600; font-size: 0.75rem;">${isTop ? 'TOP ➔' : `[${idx}]`}</span>
                        <span style="color: var(--text-primary); margin-left: 6px;">${item.ip}</span>
                    </div>
                    <div>
                        <span style="color: var(--magenta);">${item.action}</span>
                    </div>
                </div>
            `;
        });
        container.innerHTML = html;
    }

    _drawBSTVisualizer() {
        if (!this.bstCanvas) return;
        const ctx = this.bstCanvas.getContext('2d');
        const w = this.bstCanvas.width;
        const h = this.bstCanvas.height;
        ctx.clearRect(0, 0, w, h);
        
        const isLight = document.body.classList.contains('light-mode');
        ctx.fillStyle = isLight ? '#1e293b' : '#a855f7';
        ctx.font = '11px "JetBrains Mono", monospace';
        ctx.fillText("AVL BST Severity Tree (Server-Side C)", 10, 18);
        ctx.fillText("Root [Severity Index 5]", w/2 - 60, 38);
        
        ctx.strokeStyle = isLight ? 'rgba(0,0,0,0.15)' : 'rgba(168,85,247,0.3)';
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(w/2, 45); ctx.lineTo(w/2 - 50, 75);
        ctx.moveTo(w/2, 45); ctx.lineTo(w/2 + 50, 75);
        ctx.moveTo(w/2 - 50, 75); ctx.lineTo(w/2 - 80, 105);
        ctx.moveTo(w/2 - 50, 75); ctx.lineTo(w/2 - 20, 105);
        ctx.moveTo(w/2 + 50, 75); ctx.lineTo(w/2 + 20, 105);
        ctx.moveTo(w/2 + 50, 75); ctx.lineTo(w/2 + 80, 105);
        ctx.stroke();
        
        ctx.fillStyle = isLight ? '#9333ea' : '#00f0ff';
        const nodes = [
            {x: w/2, y: 45}, {x: w/2 - 50, y: 75}, {x: w/2 + 50, y: 75},
            {x: w/2 - 80, y: 105}, {x: w/2 - 20, y: 105}, {x: w/2 + 20, y: 105}, {x: w/2 + 80, y: 105}
        ];
        for (const n of nodes) {
            ctx.beginPath();
            ctx.arc(n.x, n.y, 6, 0, 2*Math.PI);
            ctx.fill();
        }
    }

    _addLogEntry(ev) {
        const div = document.createElement('div');
        div.className = 'log-entry';
        const color = ev.severity > 7 ? 'var(--red)' : ev.severity > 4 ? 'var(--orange)' : 'var(--cyan)';
        
        const time = new Date(ev.timestamp).toLocaleTimeString();
        div.innerHTML = `
            <span style="color: var(--text-muted)">[${time}]</span>
            <span style="color: ${color}; width: 24px; display: inline-block; font-weight: 600;">[S:${ev.severity}]</span>
            <span style="color: var(--text-primary); width: 110px; display: inline-block;">${ev.ip}</span>
            <span style="color: var(--magenta); width: 150px; display: inline-block; font-weight: 500;">${ev.action}</span>
            <span style="color: var(--text-secondary)">P:${ev.port}</span>
            <span style="float: right; font-weight: 600; color: ${ev.status === 'SUCCESS' ? 'var(--green)' : ev.status === 'BLOCKED' ? 'var(--yellow)' : 'var(--red)'}">${ev.status}</span>
        `;
        this.logFeed.appendChild(div);
        if (this.logFeed.childNodes.length > 60) this.logFeed.removeChild(this.logFeed.firstChild);
        this.logFeed.scrollTop = this.logFeed.scrollHeight;
    }

    _addAlertEntry(al) {
        const div = document.createElement('div');
        div.className = 'alert-entry';
        div.style.borderLeft = '4px solid var(--red)';
        div.style.padding = '8px 12px';
        div.style.marginBottom = '8px';
        div.style.background = 'rgba(255,51,85,0.08)';
        div.style.borderRadius = 'var(--radius-sm)';
        
        const time = new Date(al.timestamp).toLocaleTimeString();
        div.innerHTML = `
            <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                <strong style="color: var(--red); font-size: 0.95rem;">🚨 ${al.type}</strong>
                <span style="color: var(--text-muted); font-size: 0.8rem;">${time}</span>
            </div>
            <div style="color: var(--text-primary); font-size: 0.85rem; margin-bottom: 2px;">${al.message}</div>
            <div style="color: var(--text-secondary); font-size: 0.8rem; font-family: 'JetBrains Mono', monospace;">${al.details}</div>
        `;
        this.alertFeed.appendChild(div);
        if (this.alertFeed.childNodes.length > 30) this.alertFeed.removeChild(this.alertFeed.firstChild);
        this.alertFeed.scrollTop = this.alertFeed.scrollHeight;
    }

    _updateTimelineChart(threatCount) {
        const time = new Date().toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' });
        this.timelineData.labels.push(time);
        this.timelineData.datasets[0].data.push(threatCount);

        if (this.timelineData.labels.length > 25) {
            this.timelineData.labels.shift();
            this.timelineData.datasets[0].data.shift();
        }
        this.timelineChart.update('none');
    }

    _updateAttackChart(type) {
        let idx = -1;
        if (type.includes("Brute")) idx = 0;
        else if (type.includes("DDoS")) idx = 1;
        else if (type.includes("Privilege") || type.includes("Escalation")) idx = 2;
        else if (type.includes("Scan")) idx = 3;
        else if (type.includes("Exfil") || type.includes("Data")) idx = 4;
        
        if (idx >= 0) {
            this.attackDistData.datasets[0].data[idx]++;
            this.attackChart.update();
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new Dashboard();
});
