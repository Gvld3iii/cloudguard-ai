output "dynamodb_table_name" {
  description = "DynamoDB threat events table name"
  value       = aws_dynamodb_table.threats.name
}

output "dynamodb_table_arn" {
  description = "DynamoDB threat events table ARN"
  value       = aws_dynamodb_table.threats.arn
}

output "sns_topic_arn" {
  description = "SNS alert topic ARN"
  value       = aws_sns_topic.alerts.arn
}

output "analyzer_lambda_arn" {
  description = "Analyzer Lambda function ARN"
  value       = aws_lambda_function.analyzer.arn
}

output "responder_lambda_arn" {
  description = "Responder Lambda function ARN"
  value       = aws_lambda_function.responder.arn
}

output "waf_acl_arn" {
  description = "WAF Web ACL ARN"
  value       = aws_wafv2_web_acl.main.arn
}

output "blocked_ips_set_arn" {
  description = "WAF blocked IPs set ARN — used by the responder to auto-block"
  value       = aws_wafv2_ip_set.blocked_ips.arn
}

output "lambda_role_arn" {
  description = "Lambda execution role ARN"
  value       = aws_iam_role.lambda_exec.arn
}
