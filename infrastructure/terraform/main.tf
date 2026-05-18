# ── DynamoDB — Threat Events Store ───────────────────────────────────────────

resource "aws_dynamodb_table" "threats" {
  name         = "${var.dynamodb_table_name}-${var.environment}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  range_key    = "timestamp"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  attribute {
    name = "severity"
    type = "S"
  }

  global_secondary_index {
    name            = "severity-timestamp-index"
    hash_key        = "severity"
    range_key       = "timestamp"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  tags = {
    Name = "${var.project_name}-threats-${var.environment}"
  }
}

# ── SNS — Threat Alert Notifications ─────────────────────────────────────────

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts-${var.environment}"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.sns_alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.sns_alert_email
}

# ── IAM — Lambda Execution Role ───────────────────────────────────────────────

resource "aws_iam_role" "lambda_exec" {
  name = "${var.project_name}-lambda-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "lambda_policy" {
  name = "${var.project_name}-lambda-policy-${var.environment}"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem"
        ]
        Resource = [
          aws_dynamodb_table.threats.arn,
          "${aws_dynamodb_table.threats.arn}/index/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "wafv2:UpdateIPSet",
          "wafv2:GetIPSet"
        ]
        Resource = "*"
      }
    ]
  })
}

# ── CloudWatch Logs ───────────────────────────────────────────────────────────

resource "aws_cloudwatch_log_group" "analyzer" {
  name              = "/aws/lambda/${var.project_name}-analyzer-${var.environment}"
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "responder" {
  name              = "/aws/lambda/${var.project_name}-responder-${var.environment}"
  retention_in_days = var.log_retention_days
}

# ── Lambda — Analyzer (5 Agents) ─────────────────────────────────────────────

resource "aws_lambda_function" "analyzer" {
  function_name = "${var.project_name}-analyzer-${var.environment}"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  memory_size   = var.lambda_memory_mb
  timeout       = var.lambda_timeout_sec

  filename         = "${path.module}/../../backend/lambda/analyzer/handler.zip"
  source_code_hash = filebase64sha256("${path.module}/../../backend/lambda/analyzer/handler.zip")

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.threats.name
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      ENVIRONMENT    = var.environment
    }
  }

  depends_on = [aws_cloudwatch_log_group.analyzer]
}

# ── Lambda — Responder (Auto-block) ──────────────────────────────────────────

resource "aws_lambda_function" "responder" {
  function_name = "${var.project_name}-responder-${var.environment}"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.11"
  handler       = "handler.lambda_handler"
  memory_size   = var.lambda_memory_mb
  timeout       = var.lambda_timeout_sec

  filename         = "${path.module}/../../backend/lambda/responder/handler.zip"
  source_code_hash = filebase64sha256("${path.module}/../../backend/lambda/responder/handler.zip")

  environment {
    variables = {
      DYNAMODB_TABLE = aws_dynamodb_table.threats.name
      SNS_TOPIC_ARN  = aws_sns_topic.alerts.arn
      ENVIRONMENT    = var.environment
    }
  }

  depends_on = [aws_cloudwatch_log_group.responder]
}

# ── EventBridge — Route Threat Events ────────────────────────────────────────

resource "aws_cloudwatch_event_rule" "critical_threats" {
  name        = "${var.project_name}-critical-threats-${var.environment}"
  description = "Routes critical threat events to the responder Lambda"

  event_pattern = jsonencode({
    source      = ["cloudguard.ai"]
    detail-type = ["ThreatDetected"]
    detail = {
      severity = ["critical"]
    }
  })
}

resource "aws_cloudwatch_event_target" "responder" {
  rule      = aws_cloudwatch_event_rule.critical_threats.name
  target_id = "ResponderLambda"
  arn       = aws_lambda_function.responder.arn
}

resource "aws_lambda_permission" "eventbridge_responder" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.critical_threats.arn
}

# ── WAF — Rate Limiting & IP Blocking ────────────────────────────────────────

resource "aws_wafv2_ip_set" "blocked_ips" {
  name               = "${var.project_name}-blocked-ips-${var.environment}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = []

  tags = {
    Name = "${var.project_name}-blocked-ips"
  }
}

resource "aws_wafv2_web_acl" "main" {
  name  = "${var.project_name}-waf-${var.environment}"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "BlockedIPs"
    priority = 1

    action {
      block {}
    }

    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ips.arn
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockedIPs"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitRule"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimit"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-waf"
    sampled_requests_enabled   = true
  }
}
