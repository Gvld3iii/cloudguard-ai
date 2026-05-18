# CloudGuard AI

> **Multi-agent AI security platform.** Five specialized agents protect your cloud infrastructure in real time — detecting intrusions, scanning for exposed secrets, analyzing network traffic, hunting malware, and parsing logs for audit anomalies.

[![Deploy](https://github.com/Gvld3iii/cloudguard-ai/actions/workflows/backend-ci.yml/badge.svg)](https://github.com/Gvld3iii/cloudguard-ai/actions/workflows/backend-ci.yml)
[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Gvld3iii/cloudguard-ai/blob/main/sentinel_demo.ipynb)

---

## The Squad

<table>
  <tr>
    <td align="center" width="180">
      <img src="docs/architecture/agents/threathound.png" width="160"/><br/>
      <b>🐕 ThreatHound</b><br/>
      <sub>Intrusion Detection</sub>
    </td>
    <td align="center" width="180">
      <img src="docs/architecture/agents/vaultguard.png" width="160"/><br/>
      <b>🔐 VaultGuard</b><br/>
      <sub>Secrets & Credentials</sub>
    </td>
    <td align="center" width="180">
      <img src="docs/architecture/agents/netsentinel.png" width="160"/><br/>
      <b>🌐 NetSentinel</b><br/>
      <sub>Network Analysis</sub>
    </td>
    <td align="center" width="180">
      <img src="docs/architecture/agents/phagekiller.png" width="160"/><br/>
      <b>🦠 PhageKiller</b><br/>
      <sub>Malware & Process Monitor</sub>
    </td>
    <td align="center" width="180">
      <img src="docs/architecture/agents/auditmind.png" width="160"/><br/>
      <b>🧠 AuditMind</b><br/>
      <sub>Log Intelligence</sub>
    </td>
  </tr>
</table>

---

## What Each Agent Does

### 🐕 ThreatHound — Intrusion Detection
Monitors login attempts, port scans, DDoS patterns, and geo-anomalous access. Fires on brute force attacks, credential stuffing, and known malicious IPs.

| Rule | Trigger | Action |
|---|---|---|
| `BRUTE_FORCE_DETECTED` | ≥10 failed login attempts | `block_ip` / `rate_limit` |
| `PORT_SCAN_DETECTED` | ≥20 ports probed | `block_ip` |
| `KNOWN_MALICIOUS_IP` | Known bad IP prefix | `block_ip_immediate` |
| `GEO_ANOMALY_DETECTED` | Unusual country/region | `require_mfa` |
| `DDoS_PATTERN_DETECTED` | ≥500 req/min | `rate_limit_aggressive` |
| `CREDENTIAL_STUFFING` | High-volume automated logins | `block_ip` |

---

### 🔐 VaultGuard — Secrets & Credential Protection
Scans code, logs, `.env` files, and any text content for exposed secrets. Catches 12 pattern types including cloud keys, tokens, and hardcoded passwords.

| Rule | What It Catches |
|---|---|
| `AWS_ACCESS_KEY` | `AKIA...` key IDs |
| `GITHUB_TOKEN` | `ghp_...` personal access tokens |
| `OPENAI_API_KEY` | `sk-...` API keys |
| `STRIPE_KEY` | Live and test Stripe keys |
| `PRIVATE_KEY` | RSA, EC, OpenSSH private keys |
| `DATABASE_URL_WITH_CREDS` | Connection strings with embedded passwords |
| `HARDCODED_PASSWORD` | `password = "..."` patterns |
| `JWT_TOKEN` | Exposed session tokens |

---

### 🌐 NetSentinel — Network Traffic Analysis
Analyzes connections for C2 beaconing, data exfiltration, lateral movement, DNS tunneling, and Tor usage.

| Rule | Trigger | Action |
|---|---|---|
| `C2_BEACON_PORT` | Connection to ports 4444, 31337, 6667... | `block_connection` |
| `DATA_EXFILTRATION` | >100MB outbound to external IP | `block_connection` |
| `LATERAL_MOVEMENT` | Internal SMB/RDP/SSH between hosts | `alert_and_monitor` |
| `DNS_TUNNELING` | Encoded payload in DNS query | `block_dns_query` |
| `BEACONING_PATTERN` | Regular small packets to external host | `block_connection` |
| `TOR_NETWORK_DETECTED` | Connection to Tor ports | `alert_and_monitor` |

---

### 🦠 PhageKiller — Malware & Process Monitor
Watches running processes for ransomware patterns, cryptominers, reverse shells, and suspicious parent-child spawns.

| Rule | Trigger | Action |
|---|---|---|
| `KNOWN_MALWARE_PROCESS` | mimikatz, xmrig, wannacry, ryuk... | `kill_process_immediate` |
| `CRYPTOMINER_DETECTED` | Known miner name or CPU >90% | `kill_process` |
| `RANSOMWARE_PATTERN` | ≥200 file ops/sec + high CPU | `kill_process_isolate_host` |
| `SUSPICIOUS_PROCESS_SPAWN` | Word/Excel spawning cmd.exe | `kill_process` |
| `PROCESS_NET_ANOMALY` | Process with >50 unexpected connections | `alert_and_monitor` |
| `SUSPICIOUS_EXEC_PATH` | Process running from /tmp or AppData\Temp | `alert` |
| `PROCESS_FORK_BOMB` | ≥20 child processes spawned | `kill_process_tree` |

---

### 🧠 AuditMind — Log Intelligence & Compliance
Parses system logs, auth logs, CloudTrail, and Windows events for privilege escalation, log tampering, and account manipulation.

| Rule | Trigger | Action |
|---|---|---|
| `PRIVILEGE_ESCALATION` | `sudo su`, `pkexec`, `visudo`... | `alert_soc` |
| `LOG_TAMPERING` | `history -c`, `rm -rf /var/log`... | `alert_soc_immediate` |
| `ACCOUNT_MANIPULATION` | `useradd`, `net user /add`... | `alert_and_review` |
| `SENSITIVE_RESOURCE_ACCESS` | Access to `/etc/shadow`, `.ssh/authorized_keys`... | `alert` |
| `CLOUDTRAIL_DELETETRAIL` | AWS audit logging disabled | `alert_soc` |
| `AUTH_FAILURE_SPIKE` | Multiple failures in single log entry | `alert` |

---

## Architecture

```
Incoming Events / Telemetry
          │
          ▼
┌─────────────────────────────────────┐
│         FastAPI Command Center       │
│         /agents/* endpoints          │
│         /sentinel/analyze            │
│         /sentinel/simulate/{scenario}│
└───────────────┬─────────────────────┘
                │
    ┌───────────┼───────────┐
    ▼           ▼           ▼
ThreatHound  VaultGuard  NetSentinel  PhageKiller  AuditMind
    │           │           │              │            │
    └───────────┴───────────┴──────────────┴────────────┘
                            │
                    Unified SentinelReport
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          DynamoDB        SNS Alerts    WAF Block
        (Event Store)   (Notifications) (Auto-Response)
```

---

## Stack

| Layer | Technology |
|---|---|
| API | FastAPI (Python) |
| Agents | 5 specialized Python analyzers |
| Database | AWS DynamoDB |
| Alerting | AWS SNS |
| WAF | AWS WAF |
| Event Bus | AWS EventBridge |
| Lambda | AWS Lambda (analyzer + responder) |
| IaC | Terraform |
| Frontend | React + Vite |
| CI/CD | GitHub Actions |

---

## Attack Scenarios

5 built-in demo scenarios hit `POST /sentinel/simulate/{scenario}`:

| Scenario | Agents Fired | What Happens |
|---|---|---|
| `ransomware` | PhageKiller + NetSentinel | Detects svchost32.exe doing 650 file ops/sec + C2 connection |
| `data_breach` | NetSentinel + AuditMind | 250MB exfiltration + `/etc/shadow` access |
| `credential_theft` | ThreatHound + VaultGuard | 87 failed logins + AWS keys found in .env |
| `insider_threat` | AuditMind | `sudo su` + `history -c` + CloudTrail deleted |
| `cryptominer` | PhageKiller + NetSentinel | xmrig at 98.5% CPU + mining pool connection |

---

## Local Setup

### Prerequisites
- Python 3.9+
- pip

### Install

```bash
git clone https://github.com/Gvld3iii/cloudguard-ai.git
cd cloudguard-ai

python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # macOS/Linux

pip install -r requirements.txt
```

### Run the API

```bash
uvicorn backend.app.main:app --reload
```

Swagger UI available at `http://localhost:8000/docs`

### Run a scenario

```bash
curl -X POST http://localhost:8000/sentinel/simulate/ransomware
curl -X POST http://localhost:8000/sentinel/simulate/credential_theft
```

### CLI

```bash
python cli/sentinel.py --scenario ransomware
python cli/sentinel.py --all
python cli/sentinel.py --live
```

### Google Colab Demo

No setup needed — runs entirely in your browser:

[![Open in Colab](https://colab.research.google.com/assets/colab-badge.svg)](https://colab.research.google.com/github/Gvld3iii/cloudguard-ai/blob/main/sentinel_demo.ipynb)

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | System status |
| `GET` | `/health` | All agents health check |
| `POST` | `/agents/threathound/analyze` | Run ThreatHound |
| `POST` | `/agents/vaultguard/scan` | Run VaultGuard |
| `POST` | `/agents/netsentinel/analyze` | Run NetSentinel |
| `POST` | `/agents/phagekiller/scan` | Run PhageKiller |
| `POST` | `/agents/auditmind/analyze` | Run AuditMind |
| `POST` | `/sentinel/analyze` | Run all agents, unified report |
| `POST` | `/sentinel/simulate/{scenario}` | Built-in attack scenarios |
| `POST` | `/threats/analyze` | CloudGuard threat analysis |
| `GET` | `/docs` | Swagger UI |

---

## Project Structure

```
cloudguard-ai/
├── backend/
│   ├── app/
│   │   ├── agents/               # 5 specialized AI agents
│   │   │   ├── threathound/
│   │   │   ├── vaultguard/
│   │   │   ├── netsentinel/
│   │   │   ├── phagekiller/
│   │   │   └── auditmind/
│   │   ├── api/                  # FastAPI route handlers
│   │   ├── core/                 # Shared models + risk engine
│   │   ├── services/             # AWS service integrations
│   │   └── utils/
│   ├── lambda/                   # AWS Lambda functions
│   └── tests/
├── cli/
│   └── sentinel.py               # Terminal CLI for all agents
├── frontend/
│   └── dashboard/                # React observability dashboard
├── infrastructure/
│   └── terraform/                # AWS infrastructure as code
├── docs/
│   └── architecture/
│       └── agents/               # Agent portrait images
├── sentinel_demo.ipynb           # Google Colab demo
└── requirements.txt
```

---

## Author

**Kharee Bellamy** — Cloud Engineer | DevOps | AI Systems Builder

[LinkedIn](https://www.linkedin.com/in/kharee-bellamy-b2534b359/) · [GitHub](https://github.com/Gvld3iii/cloudguard-ai)

---

## License

MIT