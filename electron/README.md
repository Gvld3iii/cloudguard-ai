# CloudGuard AI — Setup Guide

## Prerequisites
- Node.js 18+ (https://nodejs.org)
- Python 3.10+ (https://python.org)
- Git

## Install & Run

### 1. Clone or download the project
```bash
cd cloudguard-electron
```

### 2. Install Node dependencies
```bash
npm install
```

### 3. Install Python dependencies
```bash
pip install psutil requests
```

### 4. Start the app
```bash
npm start
```

## Build as .exe (Windows installer)
```bash
npm run build
```
The installer will appear in `dist/` folder.

## Project Structure
```
cloudguard-electron/
├── src/
│   ├── main.js        ← Electron main process (system access)
│   ├── preload.js     ← Secure bridge to renderer
│   └── index.html     ← Dashboard UI
├── agents/
│   └── agents.py      ← Real threat detection agents
├── assets/
│   └── icon.png       ← App icon
└── package.json
```

## What each file does

**main.js** — The brain. Creates the window, system tray, reads your real
CPU/RAM/processes every 3 seconds and sends to the dashboard.

**preload.js** — Security layer. Safely exposes system APIs to the UI
without giving it full Node.js access.

**index.html** — The dashboard UI you designed.

**agents.py** — Python threat detection. ThreatHound reads login failures,
VaultGuard scans files for secrets, NetSentinel checks network connections,
PhageKiller watches processes, AuditMind parses system logs.
