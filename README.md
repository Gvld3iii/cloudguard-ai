# 🛡️ CloudGuard AI

## 🚀 Overview

CloudGuard AI is an event-driven cloud threat detection and response system built using AWS-inspired architecture.

It analyzes incoming events, detects anomalies, assigns a risk score, and determines automated responses such as alerting or blocking suspicious activity.

This project is designed to demonstrate real-world cloud architecture principles, security thinking, and scalable backend design.

---

## 🧠 Problem Statement

Modern cloud environments generate massive amounts of activity logs, making it difficult to quickly identify and respond to potential threats.

Traditional systems rely on static alerts or manual investigation, which can lead to delayed response times.

CloudGuard AI solves this by:
- normalizing incoming events
- evaluating anomalies
- assigning dynamic risk scores
- triggering automated response decisions

---

## 🏗️ Architecture Overview

CloudGuard AI follows a modular, event-driven architecture:

- Event ingestion (API / simulated events)
- Event normalization
- Anomaly detection
- Risk scoring engine
- Response decision engine
- Service layer (DynamoDB, SNS, WAF - stubbed)

Future AWS integrations:
- API Gateway
- Lambda
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
   - log_only
   - send_alert
   - block_ip
6. Service layer simulates:
   - storing events (DynamoDB)
   - sending alerts (SNS)
   - blocking IPs (WAF)

---

## 🧪 API Endpoints

| Endpoint | Method | Description |
|--------|--------|------------|
| `/` | GET | Root status |
| `/health` | GET | Health check |
| `/simulate` | POST | Simulate threat events |
| `/threats/analyze` | POST | Analyze real event payload |

Swagger UI: