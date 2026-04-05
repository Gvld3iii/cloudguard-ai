# 🛡️ CloudGuard AI

## 🚀 Overview

CloudGuard AI is an event-driven cloud threat detection and response system built using AWS-inspired architecture.

It analyzes incoming events, detects anomalies, assigns a risk score, and determines automated responses such as alerting or blocking suspicious activity.

This project demonstrates real-world cloud architecture principles, security-focused design, and scalable backend engineering.

---

## 🧠 Problem Statement

Modern cloud environments generate massive amounts of activity logs, making it difficult to quickly identify and respond to potential threats.

Traditional systems rely on static alerts or manual investigation, which can lead to delayed response times.

CloudGuard AI solves this by:
- Normalizing incoming events
- Evaluating anomalies
- Assigning dynamic risk scores
- Triggering automated response decisions

---

## 🏗️ Architecture Overview

CloudGuard AI follows a modular, event-driven architecture:

- Event ingestion (API / simulated events)
- Event normalization
- Anomaly detection
- Risk scoring engine
- Response decision engine
- Service layer (DynamoDB, SNS, WAF — stubbed)

### Future AWS Integrations

- API Gateway  
- AWS Lambda  
- EventBridge  
- DynamoDB  
- SNS  
- WAF  
- CloudTrail  

---

## ⚙️ How It Works

1. A security event is received via API  
2. The event is normalized into a structured format  
3. Anomaly rules evaluate suspicious behavior  
4. A risk score (0–100) is calculated  
5. A response decision is made:
   - `log_only`
   - `send_alert`
   - `block_ip`
6. The service layer simulates:
   - Storing events (DynamoDB)
   - Sending alerts (SNS)
   - Blocking IPs (WAF)

---

## 🧪 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Root status |
| `/health` | GET | Health check |
| `/simulate` | POST | Simulate threat events |
| `/threats/analyze` | POST | Analyze real event payload |

### Swagger UI
http://127.0.0.1:8000/docs

---

## 🔥 Example Simulation

### Request

```json
{
  "event_type": "login_attempt",
  "source_ip": "192.168.1.55",
  "actor": "unknown-user",
  "region": "eu-central-1",
  "api_calls_last_minute": 140,
  "failed_logins": 7,
  "privileged_action": true
}
```

### Response

```json
{
  "risk": {
    "score": 100,
    "severity": "critical"
  },
  "decision": {
    "action": "block_ip"
  }
}
```

---

## 🧠 Key Features

- Event normalization layer  
- Rule-based anomaly detection  
- Dynamic risk scoring engine  
- Automated response decision system  
- Modular service abstraction layer  
- Fully tested backend (Pytest)  

---

## 🧪 Running Locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn backend.app.main:app --reload
```

---

## 🧪 Run Tests

```bash
python -m pytest backend/tests -v
```

---

## 🧬 Future Vision: Sentinel AI

CloudGuard AI is the foundation for Sentinel AI, a next-generation cloud security platform.

Planned evolution:

- Multi-cloud monitoring (AWS, Azure, GCP)  
- AI-based anomaly detection  
- Real-time threat intelligence  
- Autonomous incident response  
- Centralized security command dashboard  

---

## 💡 What This Project Demonstrates

- Cloud architecture design thinking  
- Security-first system design  
- Event-driven backend systems  
- Scalable and modular code structure  
- Real-world API development and testing  

---

## 👨‍💻 Author

Kharee Bellamy  
Cloud Engineer | DevOps | AI Systems Builder