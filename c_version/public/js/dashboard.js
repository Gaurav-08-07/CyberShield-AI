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
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#8a8aa0' } } }, borderwidth: 0 }
        });
    }

    _bindControls() {
        document.getElementById('btn-start').addEventListener('click', () => this.start());
        document.getElementById('btn-stop').addEventListener('click', () => this.stop());
        document.getElementById('btn-reset').addEventListener('click', () => {
            this.logFeed.innerHTML = '';
            this.alertFeed.innerHTML = '';
        });
        document.getElementById('btn-theme').addEventListener('click', () => {
            document.body.classList.toggle('light-mode');
            const isLight = document.body.classList.contains('light-mode');
            document.getElementById('btn-theme').innerHTML = isLight ? '🌙 Dark Mode' : '☀️ Light Mode';
            if(this.timelineChart) this.timelineChart.update();
            if(this.attackChart) this.attackChart.update();
        });
        document.getElementById('speed-slider').addEventListener('input', (e) => {
            this.speed = parseInt(e.target.value, 10);
            document.getElementById('speed-value').textContent = this.speed;
            fetch(`/api/speed?val=${this.speed}`);
        });
    }

    start() {
        if (this.isRunning) return;
        this.isRunning = true;
        document.getElementById('btn-start').classList.add('active');
        fetch(`/api/speed?val=${this.speed}`);
        this.loop = setInterval(() => this._tick(), 500);
    }

    stop() {
        this.isRunning = false;
        document.getElementById('btn-start').classList.remove('active');
        clearInterval(this.loop);
    }

    async _tick() {
        try {
            const res = await fetch('/api/state');
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
            
            const util = (data.stats.queueSize / 500) * 100;
            document.getElementById('queue-util').textContent = util.toFixed(1) + '%';
            document.getElementById('queue-total').textContent = data.stats.queueTotal;
            document.getElementById('queue-bar').style.width = util + '%';
            
            // Update timeline
            if (data.alerts.length > 0) {
                this._updateTimelineChart(data.alerts.length);
            } else if (Math.random() < 0.2) {
                this._updateTimelineChart(0);
            }

            // Draw a fake BST for visual effect since we don't transfer the whole tree JSON
            this._drawFakeBST();

        } catch (e) {
            console.error("Backend connection failed", e);
        }
    }

    _drawFakeBST() {
        if (!this.bstCanvas) return;
        const ctx = this.bstCanvas.getContext('2d');
        const w = this.bstCanvas.width;
        const h = this.bstCanvas.height;
        ctx.clearRect(0, 0, w, h);
        
        const isLight = document.body.classList.contains('light-mode');
        ctx.fillStyle = isLight ? '#1e293b' : '#00f0ff';
        ctx.font = '10px monospace';
        ctx.fillText("BST Processing Active (Server-side)", 20, 20);
        ctx.fillText("Root -> [Avg Severity Data]", w/2 - 40, 40);
        
        // Just a decorative representation
        ctx.strokeStyle = isLight ? 'rgba(0,0,0,0.1)' : 'rgba(0,240,255,0.2)';
        ctx.beginPath();
        ctx.moveTo(w/2, 50); ctx.lineTo(w/2 - 40, 80);
        ctx.moveTo(w/2, 50); ctx.lineTo(w/2 + 40, 80);
        ctx.stroke();
        
        ctx.beginPath();
        ctx.arc(w/2, 45, 5, 0, 2*Math.PI);
        ctx.arc(w/2 - 40, 80, 5, 0, 2*Math.PI);
        ctx.arc(w/2 + 40, 80, 5, 0, 2*Math.PI);
        ctx.fill();
    }

    _addLogEntry(ev) {
        const div = document.createElement('div');
        div.className = 'log-entry';
        const color = ev.severity > 7 ? 'var(--red)' : ev.severity > 4 ? 'var(--orange)' : 'var(--cyan)';
        
        const time = new Date(ev.timestamp).toLocaleTimeString();
        div.innerHTML = `
            <span style="color: var(--text-muted)">[${time}]</span>
            <span style="color: ${color}; width: 20px; display: inline-block;">[${ev.severity}]</span>
            <span style="color: var(--text-primary); width: 100px; display: inline-block;">${ev.ip}</span>
            <span style="color: var(--magenta); width: 140px; display: inline-block;">${ev.action}</span>
            <span style="color: var(--text-secondary)">P:${ev.port}</span>
            <span style="float: right; color: ${ev.status === 'SUCCESS' ? 'var(--green)' : 'var(--red)'}">${ev.status}</span>
        `;
        this.logFeed.appendChild(div);
        if (this.logFeed.childNodes.length > 50) this.logFeed.removeChild(this.logFeed.firstChild);
        this.logFeed.scrollTop = this.logFeed.scrollHeight;
    }

    _addAlertEntry(al) {
        const div = document.createElement('div');
        div.className = 'alert-entry';
        const time = new Date(al.timestamp).toLocaleTimeString();
        div.innerHTML = `
            <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                <strong style="color: var(--red)">${al.type}</strong>
                <span style="color: var(--text-muted); font-size: 0.8rem;">${time}</span>
            </div>
            <div style="color: var(--text-primary); font-size: 0.85rem; margin-bottom: 2px;">${al.message}</div>
            <div style="color: var(--text-secondary); font-size: 0.8rem;">${al.details}</div>
        `;
        this.alertFeed.appendChild(div);
        if (this.alertFeed.childNodes.length > 20) this.alertFeed.removeChild(this.alertFeed.firstChild);
        this.alertFeed.scrollTop = this.alertFeed.scrollHeight;
    }

    _updateTimelineChart(threatCount) {
        const time = new Date().toLocaleTimeString([], { hour12: false, minute: '2-digit', second: '2-digit' });
        this.timelineData.labels.push(time);
        this.timelineData.datasets[0].data.push(threatCount);

        if (this.timelineData.labels.length > 20) {
            this.timelineData.labels.shift();
            this.timelineData.datasets[0].data.shift();
        }
        this.timelineChart.update('none');
    }

    _updateAttackChart(type) {
        let idx = -1;
        if (type.includes("Brute")) idx = 0;
        else if (type.includes("DDoS")) idx = 1;
        else if (type.includes("Privilege")) idx = 2;
        else if (type.includes("Scan")) idx = 3;
        else if (type.includes("Exfil")) idx = 4;
        
        if (idx >= 0) {
            this.attackDistData.datasets[0].data[idx]++;
            this.attackChart.update();
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.app = new Dashboard();
});
