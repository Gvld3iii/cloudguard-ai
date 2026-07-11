const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('cloudguard', {
  // System
  getSystemStats: () => ipcRenderer.invoke('get-system-stats'),
  runScan: () => ipcRenderer.invoke('run-scan'),
  getThreatScan: () => ipcRenderer.invoke('get-threat-scan'),
  killProcess: (pid) => ipcRenderer.invoke('kill-process', pid),

  // PhageKiller / YARA
  scanFile: (filePath) => ipcRenderer.invoke('scan-file', filePath),
  scanFileDialog: () => ipcRenderer.invoke('scan-file-dialog'),
  getYaraStatus: () => ipcRenderer.invoke('get-yara-status'),
  updateYaraRules: () => ipcRenderer.invoke('update-yara-rules'),

  // VaultGuard
  runVaultScan: (scanPath) => ipcRenderer.invoke('run-vault-scan', scanPath),

  // NetSentinel
  runNetSentinel: () => ipcRenderer.invoke('run-netsentinel'),

  // AuditMind
  runAuditMind: (hours) => ipcRenderer.invoke('run-auditmind', hours),

  // Active Firewall
  blockIP: (ip) => ipcRenderer.invoke('block-ip', ip),
  unblockIP: (ip) => ipcRenderer.invoke('unblock-ip', ip),
  getFirewallStatus: () => ipcRenderer.invoke('firewall-status'),
  autoBlock: () => ipcRenderer.invoke('auto-block'),
  listBlocked: () => ipcRenderer.invoke('list-blocked'),

  // Settings
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),

  // Window
  minimize: () => ipcRenderer.invoke('minimize-window'),
  maximize: () => ipcRenderer.invoke('maximize-window'),
  close: () => ipcRenderer.invoke('close-window'),
  openDownloads: () => ipcRenderer.invoke('open-downloads'),

  // Listeners
  onSystemStats: (cb) => ipcRenderer.on('system-stats', (_, d) => cb(d)),
  onThreatScan: (cb) => ipcRenderer.on('threat-scan', (_, d) => cb(d)),
  onDownloadScan: (cb) => ipcRenderer.on('download-scan', (_, d) => cb(d)),
  onYaraUpdate: (cb) => ipcRenderer.on('yara-update', (_, d) => cb(d)),
  onVaultScan: (cb) => ipcRenderer.on('vault-scan', (_, d) => cb(d)),
  onNetSentinelScan: (cb) => ipcRenderer.on('netsentinel-scan', (_, d) => cb(d)),
  onAuditMindScan: (cb) => ipcRenderer.on('auditmind-scan', (_, d) => cb(d)),
  onTriggerScan: (cb) => ipcRenderer.on('trigger-scan', () => cb()),
  removeAllListeners: (ch) => ipcRenderer.removeAllListeners(ch)
})