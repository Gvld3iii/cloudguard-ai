# Cost Optimization

## Goal
Build a portfolio-worthy project that demonstrates strong AWS architectural thinking without creating unnecessary spend.

## Cost Decisions

### 1. Serverless First
Use Lambda and EventBridge for the MVP to reduce always-on infrastructure costs.

### 2. DynamoDB for Lightweight Threat Storage
DynamoDB provides flexible scaling and low operational overhead for event-driven storage.

### 3. S3 for Logs and Static Assets
S3 is low cost and works well for log retention, static docs, screenshots, and future frontend hosting.

### 4. Small Demo Scope
Use mocked or simulated threat events during development to avoid unnecessary infrastructure churn.

### 5. Environment Separation
Keep dev and prod configurations separate to avoid accidental overprovisioning.

## Future Cost Controls
- lifecycle policies for S3
- DynamoDB TTL for old event data
- budget alarms
- CloudWatch cost monitoring
- reduced alert noise