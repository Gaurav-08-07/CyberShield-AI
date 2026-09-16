/* ============================================================
   log-generator.js
   Produces realistic synthetic cyber-security log events.
   Periodically injects coordinated attack scenarios.
   ============================================================ */

const LOG_TYPES = {
    LOGIN_SUCCESS:        { label: 'LOGIN_SUCCESS',        baseSeverity: 5,   icon: '🔓' },
    LOGIN_FAILED:         { label: 'LOGIN_FAILED',         baseSeverity: 35,  icon: '🔐' },
    PORT_SCAN:            { label: 'PORT_SCAN',            baseSeverity: 60,  icon: '🔍' },
    FILE_ACCESS:          { label: 'FILE_ACCESS',          baseSeverity: 10,  icon: '📄' },
    PRIVILEGE_ESCALATION: { label: 'PRIVILEGE_ESCALATION', baseSeverity: 80,  icon: '⚡' },
    MALWARE_DETECTED:     { label: 'MALWARE_DETECTED',     baseSeverity: 95,  icon: '🦠' },
    DDOS_TRAFFIC:         { label: 'DDOS_TRAFFIC',         baseSeverity: 75,  icon: '🌊' },
    DATA_EXFILTRATION:    { label: 'DATA_EXFILTRATION',    baseSeverity: 90,  icon: '📤' },
    FIREWALL_BLOCK:       { label: 'FIREWALL_BLOCK',       baseSeverity: 40,  icon: '🛡️' },
    AUTH_TOKEN_EXPIRED:   { label: 'AUTH_TOKEN_EXPIRED',   baseSeverity: 15,  icon: '⏰' },
    SSH_CONNECTION:       { label: 'SSH_CONNECTION',        baseSeverity: 25,  icon: '🖥️' },
    DNS_QUERY:            { label: 'DNS_QUERY',            baseSeverity: 8,   icon: '🌐' },
    SUSPICIOUS_DOWNLOAD:  { label: 'SUSPICIOUS_DOWNLOAD',  baseSeverity: 70,  icon: '⬇️' },
    CONFIG_CHANGE:        { label: 'CONFIG_CHANGE',        baseSeverity: 45,  icon: '⚙️' },
};

const NORMAL_EVENT_WEIGHTS = [
    { type: 'LOGIN_SUCCESS',       weight: 25 },
    { type: 'LOGIN_FAILED',        weight: 8  },
    { type: 'FILE_ACCESS',         weight: 20 },
    { type: 'DNS_QUERY',           weight: 22 },
    { type: 'SSH_CONNECTION',      weight: 6  },
    { type: 'AUTH_TOKEN_EXPIRED',  weight: 5  },
    { type: 'FIREWALL_BLOCK',      weight: 5  },
    { type: 'CONFIG_CHANGE',       weight: 3  },
    { type: 'PORT_SCAN',           weight: 2  },
    { type: 'SUSPICIOUS_DOWNLOAD', weight: 2  },
    { type: 'PRIVILEGE_ESCALATION',weight: 1  },
    { type: 'MALWARE_DETECTED',    weight: 0.5},
    { type: 'DATA_EXFILTRATION',   weight: 0.3},
    { type: 'DDOS_TRAFFIC',        weight: 0.2},
];

const KNOWN_MALICIOUS_IPS = [
    '185.220.101.42',
    '45.33.32.156',
    '198.51.100.77',
    '203.0.113.66',
    '91.219.236.13',
    '77.247.181.162',
    '192.42.116.211',
];

const INTERNAL_IPS = [
    '10.0.1.15', '10.0.1.22', '10.0.1.38', '10.0.2.5',
    '10.0.2.11', '10.0.3.7', '10.0.3.19', '10.0.4.2',
    '172.16.0.100', '172.16.0.101', '172.16.1.50',
];

const USERNAMES = [
    'admin', 'root', 'jsmith', 'agarcia', 'mbrown', 'lchen',
    'kpatel', 'rwilson', 'system', 'svc_backup', 'deploy_bot',
    'dba_user', 'webadmin', 'dev_ops', 'guest',
];

const PROTOCOLS = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'SSH', 'DNS', 'FTP', 'SMTP', 'ICMP'];

const COMMON_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443, 3389, 21, 25, 53, 110, 143, 993, 995, 6379, 27017, 9200];


class LogGenerator {
    constructor() {
        this.eventId = 0;
        this.sessionCounter = 0;
        this.activeSessions = {};          // sessionId → { ip, user, events }
        this.attackScenarios = [];          // queued attack scenarios
        this.attackCooldown = 0;
        this._buildWeightedTable();
    }

    _buildWeightedTable() {
        this.weightedTypes = [];
        for (const item of NORMAL_EVENT_WEIGHTS) {
            const count = Math.round(item.weight * 10);
            for (let i = 0; i < count; i++) {
                this.weightedTypes.push(item.type);
            }
        }
    }

    /** Generate a single random log event. */
    generate() {
        // Check for queued attack scenarios first
        if (this.attackScenarios.length > 0) {
            const event = this.attackScenarios.shift();
            event.id = ++this.eventId;
            event.timestamp = Date.now();
            return event;
        }

        const type = this.weightedTypes[Math.floor(Math.random() * this.weightedTypes.length)];
        return this._createEvent(type);
    }

    /** Generate a batch of N events (may include injected attacks). */
    generateBatch(n) {
        const events = [];

        // Occasionally inject an attack scenario
        this.attackCooldown--;
        if (this.attackCooldown <= 0 && Math.random() < 0.15) {
            this._injectAttackScenario();
            this.attackCooldown = Math.floor(Math.random() * 20) + 10;
        }

        // Flush any queued attack scenarios as a burst
        while (this.attackScenarios.length > 0) {
            events.push(this.generate());
        }

        for (let i = 0; i < n; i++) {
            events.push(this.generate());
        }
        return events;
    }

    _createEvent(type) {
        const meta = LOG_TYPES[type];
        const isMalicious = Math.random() < 0.08;
        const srcIP = isMalicious
            ? KNOWN_MALICIOUS_IPS[Math.floor(Math.random() * KNOWN_MALICIOUS_IPS.length)]
            : this._randomIP();
        const user = USERNAMES[Math.floor(Math.random() * USERNAMES.length)];
        const port = COMMON_PORTS[Math.floor(Math.random() * COMMON_PORTS.length)];
        const protocol = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];

        // Add jitter to severity
        const severity = Math.max(0, Math.min(100,
            meta.baseSeverity + Math.floor((Math.random() - 0.5) * 20)
        ));

        const sessionId = this._getOrCreateSession(srcIP, user);

        return {
            id: ++this.eventId,
            timestamp: Date.now(),
            type,
            icon: meta.icon,
            severity,
            srcIP,
            destIP: INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)],
            port,
            protocol,
            user,
            sessionId,
            message: this._generateMessage(type, srcIP, user, port),
            isMaliciousIP: KNOWN_MALICIOUS_IPS.includes(srcIP),
        };
    }

    _randomIP() {
        if (Math.random() < 0.6) {
            // Return an internal IP more often
            return INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)];
        }
        return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
    }

    _getOrCreateSession(ip, user) {
        const key = `${ip}:${user}`;
        if (!this.activeSessions[key]) {
            this.activeSessions[key] = {
                id: `SES-${++this.sessionCounter}`,
                ip, user, events: 0
            };
        }
        this.activeSessions[key].events++;
        // Expire sessions after many events
        if (this.activeSessions[key].events > 50) {
            const sid = this.activeSessions[key].id;
            delete this.activeSessions[key];
            return sid;
        }
        return this.activeSessions[key].id;
    }

    _generateMessage(type, ip, user, port) {
        const messages = {
            LOGIN_SUCCESS:        `User '${user}' successfully authenticated from ${ip}`,
            LOGIN_FAILED:         `Failed login attempt for '${user}' from ${ip}`,
            PORT_SCAN:            `Port scan detected from ${ip} on port ${port}`,
            FILE_ACCESS:          `File access by '${user}' from ${ip}`,
            PRIVILEGE_ESCALATION: `Privilege escalation attempt by '${user}' from ${ip}`,
            MALWARE_DETECTED:     `Malware signature detected in traffic from ${ip}`,
            DDOS_TRAFFIC:         `Abnormal traffic volume detected from ${ip}`,
            DATA_EXFILTRATION:    `Large data transfer to external IP ${ip} by '${user}'`,
            FIREWALL_BLOCK:       `Firewall blocked connection from ${ip} to port ${port}`,
            AUTH_TOKEN_EXPIRED:   `Authentication token expired for '${user}' session`,
            SSH_CONNECTION:       `SSH connection established from ${ip} by '${user}'`,
            DNS_QUERY:            `DNS query from ${ip} resolved successfully`,
            SUSPICIOUS_DOWNLOAD:  `Suspicious file download initiated by '${user}' from ${ip}`,
            CONFIG_CHANGE:        `System configuration modified by '${user}' from ${ip}`,
        };
        return messages[type] || `Event ${type} from ${ip}`;
    }

    // ── Attack Scenario Injection ────────────────────────────

    _injectAttackScenario() {
        const scenarios = [
            () => this._bruteForceScenario(),
            () => this._portScanScenario(),
            () => this._ddosScenario(),
            () => this._privEscScenario(),
            () => this._exfiltrationScenario(),
        ];
        const pick = scenarios[Math.floor(Math.random() * scenarios.length)];
        pick();
    }

    /** Brute-force: 8–15 rapid LOGIN_FAILED from one IP. */
    _bruteForceScenario() {
        const ip = KNOWN_MALICIOUS_IPS[Math.floor(Math.random() * KNOWN_MALICIOUS_IPS.length)];
        const count = 8 + Math.floor(Math.random() * 8);
        for (let i = 0; i < count; i++) {
            const user = USERNAMES[Math.floor(Math.random() * USERNAMES.length)];
            this.attackScenarios.push({
                id: 0,
                timestamp: 0,
                type: 'LOGIN_FAILED',
                icon: '🔐',
                severity: 35 + Math.floor(Math.random() * 15),
                srcIP: ip,
                destIP: INTERNAL_IPS[0],
                port: 22,
                protocol: 'SSH',
                user,
                sessionId: `ATK-BF-${this.sessionCounter}`,
                message: `[BRUTE-FORCE] Failed login for '${user}' from ${ip}`,
                isMaliciousIP: true,
                attackType: 'BRUTE_FORCE',
            });
        }
    }

    /** Port-scan: same IP hits 12–20 different ports. */
    _portScanScenario() {
        const ip = this._randomIP();
        const ports = new Set();
        while (ports.size < 12 + Math.floor(Math.random() * 9)) {
            ports.add(Math.floor(Math.random() * 65535) + 1);
        }
        for (const port of ports) {
            this.attackScenarios.push({
                id: 0, timestamp: 0,
                type: 'PORT_SCAN',
                icon: '🔍',
                severity: 55 + Math.floor(Math.random() * 20),
                srcIP: ip,
                destIP: INTERNAL_IPS[Math.floor(Math.random() * INTERNAL_IPS.length)],
                port,
                protocol: 'TCP',
                user: 'unknown',
                sessionId: `ATK-PS-${this.sessionCounter}`,
                message: `[PORT-SCAN] Probe on port ${port} from ${ip}`,
                isMaliciousIP: KNOWN_MALICIOUS_IPS.includes(ip),
                attackType: 'PORT_SCAN',
            });
        }
    }

    /** DDoS: burst of traffic from multiple IPs. */
    _ddosScenario() {
        const attackerCount = 5 + Math.floor(Math.random() * 6);
        const eventsPerAttacker = 4 + Math.floor(Math.random() * 4);
        for (let a = 0; a < attackerCount; a++) {
            const ip = this._randomIP();
            for (let e = 0; e < eventsPerAttacker; e++) {
                this.attackScenarios.push({
                    id: 0, timestamp: 0,
                    type: 'DDOS_TRAFFIC',
                    icon: '🌊',
                    severity: 70 + Math.floor(Math.random() * 20),
                    srcIP: ip,
                    destIP: INTERNAL_IPS[0],
                    port: 80,
                    protocol: 'HTTP',
                    user: 'unknown',
                    sessionId: `ATK-DD-${this.sessionCounter}`,
                    message: `[DDOS] Flood traffic from ${ip}`,
                    isMaliciousIP: false,
                    attackType: 'DDOS',
                });
            }
        }
    }

    /** Privilege escalation chain: login → auth_fail → sudo → root. */
    _privEscScenario() {
        const ip = KNOWN_MALICIOUS_IPS[Math.floor(Math.random() * KNOWN_MALICIOUS_IPS.length)];
        const user = USERNAMES[Math.floor(Math.random() * USERNAMES.length)];
        const sid = `ATK-PE-${++this.sessionCounter}`;
        const chain = [
            { type: 'SSH_CONNECTION',       severity: 30, msg: `SSH connect from ${ip}` },
            { type: 'LOGIN_SUCCESS',        severity: 10, msg: `Login as '${user}'` },
            { type: 'LOGIN_FAILED',         severity: 40, msg: `Failed sudo attempt by '${user}'` },
            { type: 'LOGIN_FAILED',         severity: 45, msg: `Failed sudo attempt by '${user}'` },
            { type: 'PRIVILEGE_ESCALATION', severity: 85, msg: `Privilege escalation: '${user}' → root` },
            { type: 'CONFIG_CHANGE',        severity: 75, msg: `Root config change by '${user}'` },
        ];
        for (const step of chain) {
            this.attackScenarios.push({
                id: 0, timestamp: 0,
                type: step.type,
                icon: LOG_TYPES[step.type].icon,
                severity: step.severity,
                srcIP: ip, destIP: INTERNAL_IPS[0],
                port: 22, protocol: 'SSH',
                user, sessionId: sid,
                message: `[PRIV-ESC] ${step.msg}`,
                isMaliciousIP: true,
                attackType: 'PRIVILEGE_ESCALATION',
            });
        }
    }

    /** Data exfiltration: access → download → large transfer. */
    _exfiltrationScenario() {
        const ip = KNOWN_MALICIOUS_IPS[Math.floor(Math.random() * KNOWN_MALICIOUS_IPS.length)];
        const user = USERNAMES[Math.floor(Math.random() * USERNAMES.length)];
        const sid = `ATK-EX-${++this.sessionCounter}`;
        const chain = [
            { type: 'FILE_ACCESS',          severity: 20, msg: `Accessing sensitive files` },
            { type: 'FILE_ACCESS',          severity: 25, msg: `Bulk file enumeration` },
            { type: 'SUSPICIOUS_DOWNLOAD',  severity: 65, msg: `Packaging data archive` },
            { type: 'DATA_EXFILTRATION',    severity: 92, msg: `Large outbound transfer to ${ip}` },
        ];
        for (const step of chain) {
            this.attackScenarios.push({
                id: 0, timestamp: 0,
                type: step.type,
                icon: LOG_TYPES[step.type].icon,
                severity: step.severity,
                srcIP: ip, destIP: INTERNAL_IPS[0],
                port: 443, protocol: 'HTTPS',
                user, sessionId: sid,
                message: `[EXFIL] ${step.msg}`,
                isMaliciousIP: true,
                attackType: 'DATA_EXFILTRATION',
            });
        }
    }
}
