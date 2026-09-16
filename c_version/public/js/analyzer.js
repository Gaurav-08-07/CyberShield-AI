/* ============================================================
   analyzer.js
   Core analysis engine — feeds logs through all data structures,
   runs pattern-detection rules, and emits threat alerts.
   ============================================================ */

class ThreatAnalyzer {
    constructor() {
        // Data structures
        this.queue     = new LogQueue(500);
        this.ipTable   = new ThreatHashTable(128);     // IP → hit count
        this.portTable = new ThreatHashTable(128);     // IP → Set<port> (serialized)
        this.failTable = new ThreatHashTable(64);      // IP → { count, firstSeen }
        this.bst       = new SeverityBST(200);
        this.stack     = new EventStack(50);

        // Known-threat lookup table
        this.threatIntel = new ThreatHashTable(32);
        for (const ip of KNOWN_MALICIOUS_IPS) {
            this.threatIntel.put(ip, { reason: 'Known malicious IP', listed: true });
        }

        // Alert history
        this.alerts = [];
        this.alertIdCounter = 0;

        // Stats
        this.totalProcessed = 0;
        this.totalThreats   = 0;
        this.threatTimeline = [];     // { timestamp, threats, logs }
        this.attackTypeCounts = {};   // type → count

        // Rate tracking for DDoS detection
        this.requestWindow = [];      // timestamps in last N seconds
        this.REQUEST_WINDOW_MS = 5000;

        // Thresholds
        this.BRUTE_FORCE_THRESHOLD   = 5;
        this.BRUTE_FORCE_WINDOW_MS   = 60000;
        this.PORT_SCAN_THRESHOLD     = 10;
        this.PORT_SCAN_WINDOW_MS     = 30000;
        this.DDOS_RATE_THRESHOLD     = 40;   // requests per window
        this.SEVERITY_SPIKE_THRESHOLD = 70;
        this.SEVERITY_SPIKE_COUNT    = 5;

        // Privilege escalation chain to look for
        this.PRIV_ESC_CHAIN = ['SSH_CONNECTION', 'LOGIN_FAILED', 'PRIVILEGE_ESCALATION'];

        // Deduplication: alertKey → lastAlertTime
        this.recentAlerts = {};
        this.ALERT_COOLDOWN_MS = 10000;
    }

    /** Ingest raw log events into the queue. */
    ingest(events) {
        for (const event of events) {
            this.queue.enqueue(event);
        }
    }

    /** Process all pending items in the queue up to a limit. Returns new alerts. */
    processQueue(limit = 50) {
        const newAlerts = [];
        let processed = 0;

        while (!this.queue.isEmpty() && processed < limit) {
            const event = this.queue.dequeue();
            if (!event) break;
            processed++;
            this.totalProcessed++;

            // 1. Index in hash tables
            this._indexEvent(event);

            // 2. Insert into BST
            this.bst.insert(event);

            // 3. Push onto session stack
            this.stack.push(event);

            // 4. Rate tracking
            this.requestWindow.push(event.timestamp);
            this._pruneWindow(event.timestamp);

            // 5. Pattern detection
            const detectedThreats = this._detectPatterns(event);
            for (const threat of detectedThreats) {
                newAlerts.push(threat);
                this.alerts.unshift(threat); // newest first
                this.totalThreats++;
                this.attackTypeCounts[threat.attackType] =
                    (this.attackTypeCounts[threat.attackType] || 0) + 1;
            }
        }

        // Keep alerts bounded
        if (this.alerts.length > 200) {
            this.alerts = this.alerts.slice(0, 200);
        }

        // Record timeline point (every call)
        this.threatTimeline.push({
            timestamp: Date.now(),
            threats: newAlerts.length,
            totalThreats: this.totalThreats,
            logs: processed,
            totalLogs: this.totalProcessed,
            queueDepth: this.queue.size(),
        });
        // Keep last 100 timeline entries
        if (this.threatTimeline.length > 100) {
            this.threatTimeline = this.threatTimeline.slice(-100);
        }

        return newAlerts;
    }

    // ── Indexing ─────────────────────────────────────────────

    _indexEvent(event) {
        // IP hit count
        this.ipTable.increment(event.srcIP);

        // Port tracking per IP
        const portKey = `ports:${event.srcIP}`;
        let portSet = this.portTable.get(portKey);
        if (!portSet) {
            portSet = { ports: new Set(), firstSeen: event.timestamp };
            this.portTable.put(portKey, portSet);
        }
        portSet.ports.add(event.port);

        // Failed login tracking
        if (event.type === 'LOGIN_FAILED') {
            const failKey = `fail:${event.srcIP}`;
            let rec = this.failTable.get(failKey);
            if (!rec) {
                rec = { count: 0, firstSeen: event.timestamp, lastSeen: event.timestamp };
                this.failTable.put(failKey, rec);
            }
            rec.count++;
            rec.lastSeen = event.timestamp;
        }
    }

    // ── Pattern Detection ────────────────────────────────────

    _detectPatterns(event) {
        const threats = [];

        // 1. Known malicious IP
        if (this.threatIntel.has(event.srcIP)) {
            const t = this._emitAlert(
                'KNOWN_MALICIOUS_IP', 'critical',
                `Traffic from known malicious IP: ${event.srcIP}`,
                event, `malip:${event.srcIP}`
            );
            if (t) threats.push(t);
        }

        // 2. Brute force
        const failKey = `fail:${event.srcIP}`;
        const failRec = this.failTable.get(failKey);
        if (failRec &&
            failRec.count >= this.BRUTE_FORCE_THRESHOLD &&
            (event.timestamp - failRec.firstSeen) <= this.BRUTE_FORCE_WINDOW_MS
        ) {
            const t = this._emitAlert(
                'BRUTE_FORCE', 'high',
                `Brute force detected: ${failRec.count} failed logins from ${event.srcIP}`,
                event, `bf:${event.srcIP}`
            );
            if (t) threats.push(t);
            // Reset counter
            failRec.count = 0;
            failRec.firstSeen = event.timestamp;
        }

        // 3. Port scanning
        const portKey = `ports:${event.srcIP}`;
        const portRec = this.portTable.get(portKey);
        if (portRec &&
            portRec.ports.size >= this.PORT_SCAN_THRESHOLD &&
            (event.timestamp - portRec.firstSeen) <= this.PORT_SCAN_WINDOW_MS
        ) {
            const t = this._emitAlert(
                'PORT_SCAN', 'high',
                `Port scanning: ${portRec.ports.size} ports probed by ${event.srcIP}`,
                event, `ps:${event.srcIP}`
            );
            if (t) threats.push(t);
            portRec.ports.clear();
            portRec.firstSeen = event.timestamp;
        }

        // 4. DDoS indicator
        if (this.requestWindow.length >= this.DDOS_RATE_THRESHOLD) {
            const t = this._emitAlert(
                'DDOS_INDICATOR', 'critical',
                `DDoS indicator: ${this.requestWindow.length} requests in ${(this.REQUEST_WINDOW_MS / 1000).toFixed(0)}s window`,
                event, 'ddos:global'
            );
            if (t) threats.push(t);
        }

        // 5. Privilege escalation chain (stack search)
        if (event.type === 'PRIVILEGE_ESCALATION') {
            const chain = this.stack.findChain(this.PRIV_ESC_CHAIN);
            if (chain) {
                const t = this._emitAlert(
                    'PRIVILEGE_ESCALATION', 'critical',
                    `Privilege escalation chain detected for '${event.user}' from ${event.srcIP}`,
                    event, `pe:${event.srcIP}:${event.user}`
                );
                if (t) threats.push(t);
            }
        }

        // 6. Severity spike (BST range query)
        const highSevEvents = this.bst.rangeQuery(this.SEVERITY_SPIKE_THRESHOLD, 100);
        if (highSevEvents.length >= this.SEVERITY_SPIKE_COUNT) {
            const recent = highSevEvents.filter(e =>
                (event.timestamp - e.timestamp) < 15000
            );
            if (recent.length >= this.SEVERITY_SPIKE_COUNT) {
                const t = this._emitAlert(
                    'SEVERITY_SPIKE', 'high',
                    `Severity spike: ${recent.length} high-severity events (≥${this.SEVERITY_SPIKE_THRESHOLD}) in last 15s`,
                    event, 'spike:global'
                );
                if (t) threats.push(t);
            }
        }

        // 7. Data exfiltration (large outbound by type)
        if (event.type === 'DATA_EXFILTRATION') {
            const t = this._emitAlert(
                'DATA_EXFILTRATION', 'critical',
                `Data exfiltration detected: ${event.message}`,
                event, `exfil:${event.srcIP}`
            );
            if (t) threats.push(t);
        }

        return threats;
    }

    _emitAlert(attackType, level, message, triggerEvent, dedupeKey) {
        // Deduplication
        const now = Date.now();
        if (this.recentAlerts[dedupeKey] &&
            (now - this.recentAlerts[dedupeKey]) < this.ALERT_COOLDOWN_MS) {
            return null;
        }
        this.recentAlerts[dedupeKey] = now;

        return {
            id: ++this.alertIdCounter,
            timestamp: now,
            attackType,
            level,
            message,
            srcIP: triggerEvent.srcIP,
            user: triggerEvent.user,
            sessionId: triggerEvent.sessionId,
            triggerEventId: triggerEvent.id,
            icon: this._levelIcon(level),
        };
    }

    _levelIcon(level) {
        return { critical: '🚨', high: '⚠️', medium: '🔶', low: 'ℹ️' }[level] || '❓';
    }

    _pruneWindow(now) {
        const cutoff = now - this.REQUEST_WINDOW_MS;
        while (this.requestWindow.length && this.requestWindow[0] < cutoff) {
            this.requestWindow.shift();
        }
    }

    // ── Summary / Stats ──────────────────────────────────────

    getStats() {
        return {
            totalProcessed: this.totalProcessed,
            totalThreats:   this.totalThreats,
            activeIPs:      this.ipTable.count,
            queueDepth:     this.queue.size(),
            queueStats:     this.queue.getStats(),
            hashStats:      this.ipTable.getStats(),
            bstStats:       this.bst.getStats(),
            stackStats:     this.stack.getStats(),
            topIPs:         this.ipTable.topN(8),
            attackTypeCounts: { ...this.attackTypeCounts },
            timeline:       this.threatTimeline,
            currentRate:    this.requestWindow.length,
        };
    }
}
