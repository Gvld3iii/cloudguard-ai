const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, dialog, shell } = require('electron')
const path = require('path')
const si = require('systeminformation')
const { exec, spawn } = require('child_process')
const fs = require('fs')
const os = require('os')

let mainWindow
let tray
let monitorInterval
let threatInterval
let yaraUpdateInterval
let downloadWatcher = null
let pythonPath = null

// ── Find Python ───────────────────────────────────────────────────────────────
function findPython() {
  const venvPath = path.join(__dirname, '..', '.venv', 'Scripts', 'python.exe')
  if (fs.existsSync(venvPath)) { pythonPath = venvPath; return venvPath }
  pythonPath = 'python'
  return 'python'
}

// ── Window ────────────────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 750,
    minWidth: 1000,
    minHeight: 620,
    frame: false,
    backgroundColor: '#06090e',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    title: 'CloudGuard AI'
  })
  mainWindow.loadFile(path.join(__dirname, 'index.html'))
  mainWindow.on('close', (e) => {
    if (!app.isQuitting) { e.preventDefault(); mainWindow.hide() }
  })
}

// ── Tray ──────────────────────────────────────────────────────────────────────
function createTray() {
  try {
    const iconPath = path.join(__dirname, '..', 'assets', 'tray.png')
    const icon = nativeImage.createFromPath(iconPath)
    tray = new Tray(icon.isEmpty() ? nativeImage.createEmpty() : icon)
    const menu = Menu.buildFromTemplate([
      { label: 'CloudGuard AI', enabled: false },
      { type: 'separator' },
      { label: 'Open Dashboard', click: () => { mainWindow.show(); mainWindow.focus() } },
      { label: 'Run Full Scan', click: () => mainWindow.webContents.send('trigger-scan') },
      { label: 'Update YARA Rules', click: () => runYaraUpdate() },
      { type: 'separator' },
      { label: 'Quit', click: () => { app.isQuitting = true; app.quit() } }
    ])
    tray.setToolTip('CloudGuard AI — Protected')
    tray.setContextMenu(menu)
    tray.on('double-click', () => { mainWindow.show(); mainWindow.focus() })
  } catch (err) {
    console.log('Tray skipped:', err.message)
  }
}

// ── Python runner ─────────────────────────────────────────────────────────────
function runPython(scriptPath, args = [], timeoutMs = 30000) {
  return new Promise((resolve) => {
    const py = pythonPath || 'python'
    const backendApp = path.join(__dirname, '..', 'backend', 'app')
    const backend = path.join(__dirname, '..', 'backend')
    const agentsDir = path.join(__dirname, '..', 'backend', 'app', 'agents')

    const env = {
      ...process.env,
      PYTHONPATH: `${backendApp};${backend};${agentsDir}`
    }

    let output = ''
    let errorOutput = ''
    const child = spawn(py, [scriptPath, ...args], { env, timeout: timeoutMs })
    child.stdout.on('data', d => { output += d.toString() })
    child.stderr.on('data', d => { errorOutput += d.toString() })
    child.on('close', () => {
      try {
        const trimmed = output.trim()
        if (trimmed) resolve(JSON.parse(trimmed))
        else resolve({ error: errorOutput || 'No output', events: [] })
      } catch (e) {
        resolve({ error: `Parse error: ${e.message}`, raw: output.substring(0, 500) })
      }
    })
    child.on('error', err => resolve({ error: err.message }))
  })
}

// ── Script paths ──────────────────────────────────────────────────────────────
const SCRIPTS = {
  threatHound: path.join(__dirname, '..', 'backend', 'app', 'agents', 'threathound', 'threathound_live.py'),
  yaraUpdater: path.join(__dirname, '..', 'backend', 'app', 'agents', 'phagekiller', 'yara_updater.py'),
  phageScanner: path.join(__dirname, '..', 'backend', 'app', 'agents', 'phagekiller', 'phagekiller_scanner.py'),
  downloadWatcher: path.join(__dirname, '..', 'backend', 'app', 'agents', 'phagekiller', 'download_watcher.py'),
  vaultGuard: path.join(__dirname, '..', 'backend', 'app', 'agents', 'vaultguard', 'vaultguard_live.py'),
  netSentinel: path.join(__dirname, '..', 'backend', 'app', 'agents', 'netsentinel', 'netsentinel_live.py'),
  auditMind: path.join(__dirname, '..', 'backend', 'app', 'agents', 'auditmind', 'auditmind_live.py'),
  activeFirewall: path.join(__dirname, '..', 'backend', 'app', 'agents', 'firewall', 'active_firewall.py'),
}

// ── ThreatHound ───────────────────────────────────────────────────────────────
async function runThreatHound(minutes = 60) {
  return await runPython(SCRIPTS.threatHound, ['--json', '--minutes', String(minutes)], 30000)
}

// ── YARA Updater ──────────────────────────────────────────────────────────────
async function runYaraUpdate(force = false) {
  console.log('Updating YARA rules...')
  const args = ['--json']
  if (force) args.push('--force')
  const result = await runPython(SCRIPTS.yaraUpdater, args, 60000)

  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('yara-update', result)
  }
  return result
}


// ── VaultGuard secrets scan ───────────────────────────────────────────────────
async function runVaultScan(scanPath = null) {
  const args = ['--json', '--max-files', '200']
  if (scanPath) args.push('--path', scanPath)
  return await runPython(SCRIPTS.vaultGuard, args, 45000)
}


// ── NetSentinel ───────────────────────────────────────────────────────────────
async function runNetSentinel() {
  return await runPython(SCRIPTS.netSentinel, ['--json'], 30000)
}

// ── AuditMind ─────────────────────────────────────────────────────────────────
async function runAuditMind(hours = 24) {
  return await runPython(SCRIPTS.auditMind, ['--json', '--hours', String(hours)], 45000)
}

// ── Active Firewall ───────────────────────────────────────────────────────────
async function blockIP(ip) {
  return await runPython(SCRIPTS.activeFirewall, ['--block', ip, '--json'], 15000)
}

async function unblockIP(ip) {
  return await runPython(SCRIPTS.activeFirewall, ['--unblock', ip, '--json'], 15000)
}

async function getFirewallStatus() {
  return await runPython(SCRIPTS.activeFirewall, ['--status', '--json'], 10000)
}

async function autoBlockThreats() {
  return await runPython(SCRIPTS.activeFirewall, ['--auto', '--json'], 45000)
}

async function listBlockedIPs() {
  return await runPython(SCRIPTS.activeFirewall, ['--list', '--json'], 10000)
}

// ── PhageKiller file scan ─────────────────────────────────────────────────────
async function scanFile(filePath) {
  return await runPython(SCRIPTS.phageScanner, [filePath, '--json'], 20000)
}

// ── Download watcher (streaming) ──────────────────────────────────────────────
function startDownloadWatcher() {
  if (downloadWatcher) {
    try { downloadWatcher.kill() } catch (_) {}
  }

  const py = pythonPath || 'python'
  const backendApp = path.join(__dirname, '..', 'backend', 'app')
  const backend = path.join(__dirname, '..', 'backend')
  const agentsDir = path.join(__dirname, '..', 'backend', 'app', 'agents')

  const env = {
    ...process.env,
    PYTHONPATH: `${backendApp};${backend};${agentsDir}`
  }

  const downloadsPath = path.join(os.homedir(), 'Downloads')
  const desktopPath = path.join(os.homedir(), 'Desktop')

  downloadWatcher = spawn(py, [
    SCRIPTS.downloadWatcher,
    '--json',
    '--path', downloadsPath, desktopPath
  ], { env })

  let buffer = ''

  downloadWatcher.stdout.on('data', (data) => {
    buffer += data.toString()
    const lines = buffer.split('\n')
    buffer = lines.pop() // keep incomplete last line

    for (const line of lines) {
      const trimmed = line.trim()
      if (!trimmed) continue
      try {
        const event = JSON.parse(trimmed)
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('download-scan', event)
        }
        // Show notification for threats
        if (event.verdict === 'malicious' || event.verdict === 'suspicious') {
          console.log(`[PhageKiller] ${event.verdict.toUpperCase()}: ${event.file}`)
        }
      } catch (_) {}
    }
  })

  downloadWatcher.stderr.on('data', d => console.log('[Watcher]', d.toString().trim()))
  downloadWatcher.on('close', (code) => {
    console.log(`Download watcher stopped (code: ${code})`)
    downloadWatcher = null
    // Auto-restart after 5 seconds unless app is quitting
    if (!app.isQuitting) {
      setTimeout(startDownloadWatcher, 5000)
    }
  })

  console.log('Download watcher started — monitoring:', downloadsPath, desktopPath)
}

// ── Process risk ──────────────────────────────────────────────────────────────
function assessProcessRisk(process) {
  const name = (process.name || '').toLowerCase()
  const critical = ['ransomware', 'keylog', 'rootkit', 'backdoor', 'trojan']
  const suspicious = ['miner', 'crypto', 'coin', 'xmrig', 'update_helper']
  const trusted = ['cloudguard', 'explorer', 'svchost', 'system', 'registry', 'node', 'python', 'chrome', 'firefox', 'code', 'electron', 'discord', 'steam']
  if (critical.some(p => name.includes(p))) return 'CRITICAL'
  if (suspicious.some(p => name.includes(p))) return 'SUSPICIOUS'
  if ((process.cpu || 0) > 50) return 'HIGH'
  if (trusted.some(p => name.includes(p))) return 'TRUSTED'
  return 'CLEAN'
}

// ── System stats ──────────────────────────────────────────────────────────────
async function getSystemStats() {
  try {
    const [cpu, mem, processes] = await Promise.all([
      si.currentLoad().catch(() => ({ currentLoad: 0, cpus: [] })),
      si.mem().catch(() => ({ used: 0, total: 1 })),
      si.processes().catch(() => ({ list: [] }))
    ])
    const topProcesses = (processes.list || [])
      .sort((a, b) => (b.cpu || 0) - (a.cpu || 0))
      .slice(0, 10)
      .map(p => ({
        name: p.name || 'unknown',
        cpu: Math.round((p.cpu || 0) * 10) / 10,
        mem: Math.round((p.mem || 0) * 10) / 10,
        memMb: Math.round((p.memRss || 0) / 1024 / 1024),
        pid: p.pid || 0,
        risk: assessProcessRisk(p)
      }))
    return {
      cpu: Math.round(cpu.currentLoad || 0),
      cpuCores: (cpu.cpus || []).length || 8,
      ram: Math.round(((mem.used || 0) / (mem.total || 1)) * 100),
      ramUsed: Math.round((mem.used || 0) / 1024 / 1024 / 1024 * 10) / 10,
      ramTotal: Math.round((mem.total || 1) / 1024 / 1024 / 1024),
      netRx: 0, netTx: 0, diskRead: 0,
      processes: topProcesses
    }
  } catch (err) {
    console.error('System stats error:', err.message)
    return null
  }
}

// ── Monitoring loops ──────────────────────────────────────────────────────────
function startMonitoring() {
  // System stats every 3s
  monitorInterval = setInterval(async () => {
    try {
      const stats = await getSystemStats()
      if (stats && mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('system-stats', stats)
      }
    } catch (err) { console.error('Monitor error:', err.message) }
  }, 3000)

  // ThreatHound scan every 60s
  threatInterval = setInterval(async () => {
    try {
      const data = await runThreatHound(60)
      if (data && mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('threat-scan', data)
      }
    } catch (err) { console.error('ThreatHound error:', err.message) }
  }, 60000)

  // VaultGuard scan every 10 minutes
  setInterval(async () => {
    try {
      const data = await runVaultScan()
      if (data && mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vault-scan', data)
      }
    } catch (err) { console.error('VaultGuard error:', err.message) }
  }, 10 * 60 * 1000)

  // NetSentinel scan every 30 seconds
  setInterval(async () => {
    try {
      const data = await runNetSentinel()
      if (data && mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('netsentinel-scan', data)
      }
    } catch (err) { console.error('NetSentinel error:', err.message) }
  }, 30000)

  // AuditMind scan every 5 minutes
  setInterval(async () => {
    try {
      const data = await runAuditMind(24)
      if (data && mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('auditmind-scan', data)
      }
    } catch (err) { console.error('AuditMind error:', err.message) }
  }, 5 * 60 * 1000)

  // YARA update check every 24hrs
  yaraUpdateInterval = setInterval(() => runYaraUpdate(false), 24 * 60 * 60 * 1000)

  // Initial scans on startup
  setTimeout(async () => {
    const data = await runThreatHound(1440)
    if (data && mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('threat-scan', data)
  }, 3000)

  // Scan existing downloads on startup
  setTimeout(async () => {
    const py = pythonPath || 'python'
    const backendApp = path.join(__dirname, '..', 'backend', 'app')
    const agentsDir = path.join(__dirname, '..', 'backend', 'app', 'agents')
    const env = { ...process.env, PYTHONPATH: `${backendApp};${path.join(__dirname, '..', 'backend')};${agentsDir}` }
    const child = spawn(py, [SCRIPTS.downloadWatcher, '--json', '--once'], { env })
    let output = ''
    child.stdout.on('data', d => {
      output += d.toString()
      const lines = output.split('\n')
      output = lines.pop()
      for (const line of lines) {
        try {
          const event = JSON.parse(line.trim())
          if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('download-scan', event)
        } catch (_) {}
      }
    })
  }, 8000)

  // Update YARA rules on startup
  setTimeout(() => runYaraUpdate(false), 5000)

  // VaultGuard initial scan
  setTimeout(async () => {
    try {
      const data = await runVaultScan()
      if (data && mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('vault-scan', data)
      }
    } catch (err) { console.error('VaultGuard startup error:', err.message) }
  }, 15000)

  // NetSentinel initial scan
  setTimeout(async () => {
    try {
      const data = await runNetSentinel()
      if (data && mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('netsentinel-scan', data)
      }
    } catch (err) { console.error('NetSentinel startup error:', err.message) }
  }, 6000)

  // AuditMind initial scan
  setTimeout(async () => {
    try {
      const data = await runAuditMind(24)
      if (data && mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('auditmind-scan', data)
      }
    } catch (err) { console.error('AuditMind startup error:', err.message) }
  }, 20000)

  // Start download watcher
  setTimeout(() => startDownloadWatcher(), 10000)
}

// ── IPC Handlers ──────────────────────────────────────────────────────────────
ipcMain.handle('get-system-stats', async () => await getSystemStats())
ipcMain.handle('get-threat-scan', async () => await runThreatHound(1440))
ipcMain.handle('get-yara-status', async () => await runPython(SCRIPTS.yaraUpdater, ['--status', '--json'], 10000))
ipcMain.handle('update-yara-rules', async () => await runYaraUpdate(true))
ipcMain.handle('scan-file', async (event, filePath) => await scanFile(filePath))
ipcMain.handle('run-vault-scan', async (event, scanPath) => await runVaultScan(scanPath))
ipcMain.handle('run-netsentinel', async () => await runNetSentinel())
ipcMain.handle('run-auditmind', async (event, hours) => await runAuditMind(hours || 24))
ipcMain.handle('block-ip', async (event, ip) => await blockIP(ip))
ipcMain.handle('unblock-ip', async (event, ip) => await unblockIP(ip))
ipcMain.handle('firewall-status', async () => await getFirewallStatus())
ipcMain.handle('auto-block', async () => await autoBlockThreats())
ipcMain.handle('list-blocked', async () => await listBlockedIPs())

ipcMain.handle('scan-file-dialog', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'CloudGuard AI — Scan File',
    buttonLabel: 'Scan with PhageKiller',
    properties: ['openFile', 'multiSelections']
  })
  if (result.canceled || !result.filePaths.length) return null
  const scans = await Promise.all(result.filePaths.map(fp => scanFile(fp)))
  return scans
})

ipcMain.handle('run-scan', async () => {
  const [sysStats, threatData] = await Promise.all([getSystemStats(), runThreatHound(1440)])
  const threats = []
  if (sysStats?.processes) {
    sysStats.processes
      .filter(p => p.risk === 'SUSPICIOUS' || p.risk === 'CRITICAL')
      .forEach(p => threats.push({ agent: 'PhageKiller', message: `${p.name} — ${p.risk}`, severity: p.risk === 'CRITICAL' ? 'critical' : 'high', pid: p.pid }))
  }
  if (threatData?.events) threatData.events.forEach(e => threats.push(e))
  return { threats, scannedAt: new Date().toISOString(), threatScan: threatData }
})

ipcMain.handle('get-settings', () => ({
  accentColor: '#00c864', backgroundColor: '#06090e',
  agents: { ThreatHound: true, VaultGuard: true, NetSentinel: true, PhageKiller: true, AuditMind: true },
  thresholds: { riskScore: 75, cpu: 80, ram: 85, failedLogins: 5 },
  autoHeal: true, notifications: true, systemTray: true, aiTips: true, startWithWindows: false
}))

ipcMain.handle('save-settings', (event, settings) => { console.log('Settings saved'); return true })
ipcMain.handle('minimize-window', () => mainWindow?.minimize())
ipcMain.handle('maximize-window', () => mainWindow?.isMaximized() ? mainWindow.unmaximize() : mainWindow?.maximize())
ipcMain.handle('close-window', () => mainWindow?.hide())
ipcMain.handle('kill-process', async (event, pid) => new Promise(resolve => {
  exec(process.platform === 'win32' ? `taskkill /PID ${pid} /F` : `kill -9 ${pid}`, err => resolve(!err))
}))
ipcMain.handle('open-downloads', () => shell.openPath(path.join(os.homedir(), 'Downloads')))

// ── App lifecycle ─────────────────────────────────────────────────────────────
app.whenReady().then(() => {
  pythonPath = findPython()
  console.log('Python:', pythonPath)
  createWindow()
  createTray()
  startMonitoring()
})

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit() })
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow() })
app.on('before-quit', () => {
  app.isQuitting = true
  if (monitorInterval) clearInterval(monitorInterval)
  if (threatInterval) clearInterval(threatInterval)
  if (yaraUpdateInterval) clearInterval(yaraUpdateInterval)
  if (downloadWatcher) { try { downloadWatcher.kill() } catch (_) {} }
})