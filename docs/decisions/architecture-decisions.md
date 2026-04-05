# Architecture Decisions

## Project Name
CloudGuard AI

## Purpose
CloudGuard AI is an event-driven cloud threat detection and response platform built on AWS. It is designed to ingest security-relevant events, normalize them, assign risk scores, and trigger automated responses.

## Core Design Decisions

### 1. Event-Driven Architecture
The system is designed around events instead of a monolithic polling model.
This allows better scalability, lower idle cost, and cleaner integration with AWS-native services.

### 2. AWS-First MVP
The first version focuses on AWS services to keep the MVP narrow, practical, and aligned with the AWS Solutions Architect path.

### 3. Modular Backend
The backend is split into:
- API routes
- core detection logic
- service integrations
- models
- utilities

This keeps the system maintainable and allows each module to evolve independently.

### 4. Risk Score Engine
Instead of binary safe/dangerous logic, the platform uses risk scoring from 0 to 100.
This makes it easier to prioritize threats and evolve toward AI-assisted detection later.

### 5. Expandable Product Vision
CloudGuard AI is the MVP foundation for Sentinel AI, which will expand into a multi-cloud autonomous security platform.

## Initial AWS Services
- API Gateway
- Lambda
- EventBridge
- DynamoDB
- SNS
- S3
- WAF
- CloudTrail

## Why This Architecture
This design demonstrates:
- scalability
- security thinking
- event-driven cloud architecture
- modular software design
- future SaaS potential