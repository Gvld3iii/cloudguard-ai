# Security Decisions

## Security Philosophy
CloudGuard AI should follow least privilege, clear separation of duties, and secure-by-default design.

## Key Decisions

### 1. Least Privilege IAM
Each service and function should receive only the permissions it needs.

### 2. Sensitive Configuration via Environment Variables
Secrets and environment-specific configuration should not be hardcoded.
Production secrets should eventually be stored in AWS Secrets Manager or SSM Parameter Store.

### 3. Input Validation
All inbound events and API payloads should be validated before processing.

### 4. Auditability
Threat events, risk scores, and automated actions should be logged for visibility and review.

### 5. Controlled Auto-Response
Automated actions like IP blocking should be scoped and logged to reduce accidental disruption.

### 6. Separation Between Simulation and Production
Simulated threat actions for demos should not be mixed with production response logic.

## Future Security Enhancements
- Secrets Manager integration
- stronger event signing and validation
- role-based dashboard access
- alert deduplication
- real incident history tracking