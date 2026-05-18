variable "aws_region" {
  description = "AWS region to deploy CloudGuard AI"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "cloudguard-ai"
}

variable "dynamodb_table_name" {
  description = "DynamoDB table name for threat events"
  type        = string
  default     = "cloudguard-threats"
}

variable "sns_alert_email" {
  description = "Email address for SNS threat alerts"
  type        = string
  default     = ""
}

variable "lambda_memory_mb" {
  description = "Memory allocation for Lambda functions in MB"
  type        = number
  default     = 256
}

variable "lambda_timeout_sec" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "waf_rate_limit" {
  description = "Max requests per 5 minutes per IP before WAF blocks"
  type        = number
  default     = 2000
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}
