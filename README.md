# CyberShield-AI 🛡️

**Real-Time Cyber Threat Log Analyzer** powered by client-side data structures.

## Features

- **Live Simulation Engine** — Generates realistic cybersecurity log events in real-time
- **Queue (Circular Buffer)** — FIFO log ingestion with capacity visualization
- **Hash Table (IP Frequencies)** — O(1) IP hit-count tracking with top offenders
- **AVL BST (Severity Tree)** — Self-balancing binary search tree, visualized on canvas
- **Stack (Event Sequence)** — LIFO event pattern detection for PrivEsc chains
- **Threat Detection Rules** — Brute Force, Port Scan, DDoS, Privilege Escalation, Data Exfiltration
- **Custom File Analyzer** — Drag & drop `.txt`, `.log`, `.pdf` files for analysis
- **Sample Presets** — One-click Brute Force, DDoS, PrivEsc & Exfil attack logs
- **Dark/Light Mode** — Full theme toggle
- **Charts** — Live threat timeline + attack distribution doughnut chart

## Architecture

All simulation runs **100% client-side** in the browser — no server required.

```
js/data-structures.js  → LogQueue, ThreatHashTable, SeverityBST, EventStack
js/log-generator.js    → Synthetic log event generation + attack scenarios
js/analyzer.js         → Pattern detection engine (feeds through all DS)
js/dashboard.js        → UI controller, charts, visualizers
```

The `api/` folder contains lightweight Vercel serverless functions for future server-side integration (currently the app runs fully client-side).

## Deploy to Vercel

```bash
vercel deploy
```

## Run Locally

```bash
npx serve . -p 3000
# or just open index.html in a browser
```