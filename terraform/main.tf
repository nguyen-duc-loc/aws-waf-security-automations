terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# --- Lambda Packaging ---
# This assumes the Go binaries have been built in their respective directories.

data "archive_file" "add_athena_partitions_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambdas/add_athena_partitions"
  output_path = "${path.module}/lambdas/add_athena_partitions.zip"
}

data "archive_file" "partition_s3_logs_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambdas/partition_s3_logs"
  output_path = "${path.module}/lambdas/partition_s3_logs.zip"
}

data "archive_file" "log_parser_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambdas/log_parser"
  output_path = "${path.module}/lambdas/log_parser.zip"
}

# --- IAM Roles ---

resource "aws_iam_role" "log_parser_role" {
  name = "${var.stack_name}-log-parser-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# --- IAM Policies for Log Parser Role ---

# Common permissions needed by both modes
resource "aws_iam_policy" "log_parser_common_policy" {
  name   = "${var.stack_name}-log-parser-common-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${var.stack_name}-log-parser*:*"
      },
      {
        Action = [
          "wafv2:GetIPSet",
          "wafv2:UpdateIPSet"
        ]
        Effect   = "Allow"
        Resource = [
          aws_wafv2_ip_set.http_flood_set_v4[0].arn,
          aws_wafv2_ip_set.http_flood_set_v6[0].arn
        ]
        Condition = {
          Bool = {
            "aws:ResourceTag/aws-waf-security-automations/managed" = "true"
          }
        }
      }
    ]
  })
}

# Permissions for Athena mode
resource "aws_iam_policy" "log_parser_athena_policy" {
  count = var.http_flood_athena_log_parser_activated ? 1 : 0
  name   = "${var.stack_name}-log-parser-athena-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
            "athena:StartQueryExecution",
            "athena:GetQueryExecution"
        ]
        Effect   = "Allow"
        Resource = "arn:${data.aws_partition.current.partition}:athena:${var.aws_region}:${data.aws_caller_identity.current.account_id}:workgroup/*"
      },
      {
        Action = ["glue:GetTable"]
        Effect = "Allow"
        Resource = "*" # As per original CFN
      },
      {
        Action = ["s3:GetObject"]
        Effect = "Allow"
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.waf_log_bucket.id}/athena_results/*"
      }
    ]
  })
}

# Permissions for Lambda mode
resource "aws_iam_policy" "log_parser_lambda_policy" {
  count = var.http_flood_lambda_log_parser_activated ? 1 : 0
  name   = "${var.stack_name}-log-parser-lambda-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = ["s3:GetObject"]
        Effect   = "Allow"
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.waf_log_bucket.id}/AWSLogs/*"
      },
      {
        Action = ["s3:GetObject", "s3:PutObject"]
        Effect = "Allow"
        Resource = "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.waf_log_bucket.id}/${var.stack_name}-waf_log_*.json"
      }
    ]
  })
}

# Attach policies to the role
resource "aws_iam_role_policy_attachment" "log_parser_common_attachment" {
  role       = aws_iam_role.log_parser_role.name
  policy_arn = aws_iam_policy.log_parser_common_policy.arn
}

resource "aws_iam_role_policy_attachment" "log_parser_athena_attachment" {
  count      = var.http_flood_athena_log_parser_activated ? 1 : 0
  role       = aws_iam_role.log_parser_role.name
  policy_arn = aws_iam_policy.log_parser_athena_policy[0].arn
}

resource "aws_iam_role_policy_attachment" "log_parser_lambda_attachment" {
  count      = var.http_flood_lambda_log_parser_activated ? 1 : 0
  role       = aws_iam_role.log_parser_role.name
  policy_arn = aws_iam_policy.log_parser_lambda_policy[0].arn
}

resource "aws_iam_role" "add_partitions_role" {
  name = "${var.stack_name}-add-partitions-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "add_partitions_policy" {
  count = var.athena_log_parser_activated ? 1 : 0
  name   = "${var.stack_name}-add-partitions-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${var.waf_log_bucket_name}/athena_results/*",
          "arn:${data.aws_partition.current.partition}:s3:::${var.waf_log_bucket_name}",
          "arn:${data.aws_partition.current.partition}:s3:::${var.app_access_log_bucket}/athena_results/*",
          "arn:${data.aws_partition.current.partition}:s3:::${var.app_access_log_bucket}"
        ]
      },
      {
        Action   = ["athena:StartQueryExecution"]
        Effect   = "Allow"
        Resource = [module.firehose_athena_pipeline.waf_add_partition_athena_query_workgroup_arn]
      },
      {
        Action = [
          "glue:GetTable",
          "glue:GetDatabase",
          "glue:BatchCreatePartition"
        ]
        Effect   = "Allow"
        Resource = [
          "arn:${data.aws_partition.current.partition}:glue:${var.aws_region}:${data.aws_caller_identity.current.account_id}:catalog",
          "arn:${data.aws_partition.current.partition}:glue:${var.aws_region}:${data.aws_caller_identity.current.account_id}:database/${module.firehose_athena_pipeline.glue_access_logs_database_name}",
          "arn:${data.aws_partition.current.partition}:glue:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${module.firehose_athena_pipeline.glue_access_logs_database_name}/${module.firehose_athena_pipeline.glue_waf_access_logs_table_name}",
          "arn:${data.aws_partition.current.partition}:glue:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${module.firehose_athena_pipeline.glue_access_logs_database_name}/${module.firehose_athena_pipeline.glue_app_access_logs_table_name}"
        ]
      },
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:${data.aws_partition.current.partition}:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${aws_lambda_function.add_athena_partitions.function_name}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "add_partitions_attachment" {
  count      = var.athena_log_parser_activated ? 1 : 0
  role       = aws_iam_role.add_partitions_role.name
  policy_arn = aws_iam_policy.add_partitions_policy[0].arn
}

resource "aws_iam_role" "partition_s3_logs_role" {
  name = "${var.stack_name}-partition-s3-logs-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# --- Lambda Functions ---

resource "aws_lambda_function" "add_athena_partitions" {
  function_name = "${var.stack_name}-add-athena-partitions"
  role          = aws_iam_role.add_partitions_role.arn
  handler       = "bootstrap"
  runtime       = "provided.al2"
  filename      = data.archive_file.add_athena_partitions_zip.output_path
  source_code_hash = data.archive_file.add_athena_partitions_zip.output_base64sha256
}

resource "aws_lambda_function" "partition_s3_logs" {
  function_name = "${var.stack_name}-partition-s3-logs"
  role          = aws_iam_role.partition_s3_logs_role.arn
  handler       = "bootstrap"
  runtime       = "provided.al2"
  filename      = data.archive_file.partition_s3_logs_zip.output_path
  source_code_hash = data.archive_file.partition_s3_logs_zip.output_base64sha256
}

resource "aws_lambda_function" "log_parser" {
  function_name = "${var.stack_name}-log-parser"
  role          = aws_iam_role.log_parser_role.arn
  handler       = "bootstrap"
  runtime       = "provided.al2"
  filename      = data.archive_file.log_parser_zip.output_path
  source_code_hash = data.archive_file.log_parser_zip.output_base64sha256

  environment {
    variables = {
      SCOPE                      = var.scope
      LOG_TYPE                   = var.log_type
      STACK_NAME                 = var.stack_name
      IP_SET_ID_HTTP_FLOODV4     = var.http_flood_protection_log_parser_activated ? aws_wafv2_ip_set.http_flood_set_v4[0].id : ""
      IP_SET_ID_HTTP_FLOODV6     = var.http_flood_protection_log_parser_activated ? aws_wafv2_ip_set.http_flood_set_v6[0].id : ""
      IP_SET_NAME_HTTP_FLOODV4   = var.http_flood_protection_log_parser_activated ? aws_wafv2_ip_set.http_flood_set_v4[0].name : ""
      IP_SET_NAME_HTTP_FLOODV6   = var.http_flood_protection_log_parser_activated ? aws_wafv2_ip_set.http_flood_set_v6[0].name : ""
      # ... other env vars ...
    }
  }
}

# --- Event Triggers for Add Athena Partitions ---

resource "aws_cloudwatch_event_rule" "add_athena_partitions_rule" {
  count = var.athena_log_parser_activated ? 1 : 0

  name                = "${var.stack_name}-AddAthenaPartitionsRule"
  description         = "Security Automation - Add Athena Partitions"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "add_athena_partitions_target" {
  count = var.athena_log_parser_activated ? 1 : 0

  rule      = aws_cloudwatch_event_rule.add_athena_partitions_rule[0].name
  target_id = "AddAthenaPartitions"
  arn       = aws_lambda_function.add_athena_partitions.arn
  input = jsonencode({
    "glueAccessLogsDatabase" = module.firehose_athena_pipeline.glue_access_logs_database_name,
    "glueAppAccessLogsTable" = module.firehose_athena_pipeline.glue_app_access_logs_table_name,
    "glueWafAccessLogsTable" = module.firehose_athena_pipeline.glue_waf_access_logs_table_name,
    "accessLogBucket"      = var.app_access_log_bucket,
    "wafLogBucket"         = var.waf_log_bucket_name,
    "athenaWorkGroup"      = module.firehose_athena_pipeline.waf_add_partition_athena_query_workgroup_name
  })
}

# --- Event Triggers for Log Parser ---

resource "aws_cloudwatch_event_rule" "athena_waf_log_parser_rule" {
  count = var.http_flood_athena_log_parser_activated ? 1 : 0

  name                = "${var.stack_name}-AthenaWAFLogParserRule"
  description         = "Security Automation - WAF Logs Athena parser"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "athena_waf_log_parser_target" {
  count = var.http_flood_athena_log_parser_activated ? 1 : 0

  rule      = aws_cloudwatch_event_rule.athena_waf_log_parser_rule[0].name
  target_id = "LogParser"
  arn       = aws_lambda_function.log_parser.arn
  input = jsonencode({
    "resourceType"         = "LambdaAthenaWAFLogParser",
    "glueAccessLogsDatabase" = module.firehose_athena_pipeline.glue_access_logs_database_name,
    "accessLogBucket"      = var.waf_log_bucket_name,
    "glueWafAccessLogsTable" = module.firehose_athena_pipeline.glue_waf_access_logs_table_name,
    "athenaWorkGroup"      = module.firehose_athena_pipeline.waf_log_athena_query_workgroup_name
  })
}

resource "aws_s3_bucket_notification" "waf_log_bucket_notification" {
  count  = var.http_flood_lambda_log_parser_activated ? 1 : 0
  bucket = aws_s3_bucket.waf_log_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.log_parser.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "AWSLogs/"
  }

  depends_on = [aws_lambda_permission.s3_invoke_log_parser]
}

# --- Lambda Invoke Permissions ---

resource "aws_lambda_permission" "allow_cloudwatch_to_call_add_athena_partitions" {
  count = var.athena_log_parser_activated ? 1 : 0

  statement_id  = "AllowExecutionFromCloudWatchEventsForAddPartitions"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.add_athena_partitions.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.add_athena_partitions_rule[0].arn
}

resource "aws_lambda_permission" "cw_events_invoke_log_parser" {
  count = var.http_flood_athena_log_parser_activated ? 1 : 0

  statement_id  = "AllowExecutionFromCloudWatchEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.log_parser.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.athena_waf_log_parser_rule[0].arn
}

resource "aws_lambda_permission" "s3_invoke_log_parser" {
  count = var.http_flood_lambda_log_parser_activated ? 1 : 0

  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.log_parser.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.waf_log_bucket.arn
}


# --- Firehose/Athena Module ---

module "firehose_athena_pipeline" {
  source = "./modules/firehose_athena_pipeline"

  # Pass all necessary variables from the root variables.tf
  http_flood_protection_log_parser_activated = var.http_flood_protection_log_parser_activated
  athena_log_parser_activated                = var.athena_log_parser_activated
  http_flood_athena_log_parser_activated     = var.http_flood_athena_log_parser_activated
  scanners_probes_athena_log_parser_activated = var.scanners_probes_athena_log_parser_activated
  alb_scanners_probes_athena_log_parser_activated = var.alb_scanners_probes_athena_log_parser_activated
  cloudfront_scanners_probes_athena_log_parser_activated = var.cloudfront_scanners_probes_athena_log_parser_activated

  parent_stack_name   = var.stack_name
  aws_account_id      = data.aws_caller_identity.current.account_id
  aws_partition       = data.aws_partition.current.partition
  aws_region          = var.aws_region
  waf_log_bucket_arn  = aws_s3_bucket.waf_log_bucket.arn
  waf_log_bucket_name = aws_s3_bucket.waf_log_bucket.id
  delivery_stream_name  = "${var.stack_name}-waf-stream"
  glue_database_name    = "${lower(var.stack_name)}_db"
  app_access_log_bucket = var.app_access_log_bucket
  uuid                  = random_uuid.uuid.result
}

# --- Other Resources (to be created) ---

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "random_uuid" "uuid" {}

# --- IP Sets ---

resource "aws_wafv2_ip_set" "whitelist_v4" {
  name               = "${var.stack_name}-WhitelistSetIPV4"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = []
}

resource "aws_wafv2_ip_set" "whitelist_v6" {
  name               = "${var.stack_name}-WhitelistSetIPV6"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = []
}

resource "aws_wafv2_ip_set" "blacklist_v4" {
  name               = "${var.stack_name}-BlacklistSetIPV4"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = []
}

resource "aws_wafv2_ip_set" "blacklist_v6" {
  name               = "${var.stack_name}-BlacklistSetIPV6"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = []
}

resource "aws_wafv2_ip_set" "http_flood_set_v4" {
  count = var.http_flood_protection_log_parser_activated ? 1 : 0
  name               = "${var.stack_name}-HTTPFloodSetIPV4"
  scope              = var.scope
  ip_address_version = "IPV4"
  addresses          = []
}

resource "aws_wafv2_ip_set" "http_flood_set_v6" {
  count = var.http_flood_protection_log_parser_activated ? 1 : 0
  name               = "${var.stack_name}-HTTPFloodSetIPV6"
  scope              = var.scope
  ip_address_version = "IPV6"
  addresses          = []
}

# --- WAF WebACL ---

resource "aws_wafv2_web_acl" "main" {
  name  = var.stack_name
  scope = var.scope

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.stack_name}-web-acl"
    sampled_requests_enabled   = true
  }

  # Whitelist Rule
  rule {
    name     = "${var.stack_name}-WhitelistRule"
    priority = 0
    action {
      allow {}
    }
    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.whitelist_v4.arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.whitelist_v6.arn
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.stack_name}-WhitelistRule"
      sampled_requests_enabled   = true
    }
  }

  # Blacklist Rule
  rule {
    name     = "${var.stack_name}-BlacklistRule"
    priority = 1
    action {
      block {}
    }
    statement {
      or_statement {
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.blacklist_v4.arn
          }
        }
        statement {
          ip_set_reference_statement {
            arn = aws_wafv2_ip_set.blacklist_v6.arn
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.stack_name}-BlacklistRule"
      sampled_requests_enabled   = true
    }
  }

  # HTTP Flood Rule (from Log Parser)
  dynamic "rule" {
    for_each = var.http_flood_protection_log_parser_activated ? [1] : []
    content {
      name     = "${var.stack_name}-HttpFloodRegularRule"
      priority = 2
      action {
        block {}
      }
      statement {
        or_statement {
          statement {
            ip_set_reference_statement {
              arn = aws_wafv2_ip_set.http_flood_set_v4[0].arn
            }
          }
          statement {
            ip_set_reference_statement {
              arn = aws_wafv2_ip_set.http_flood_set_v6[0].arn
            }
          }
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.stack_name}-HttpFloodRegularRule"
        sampled_requests_enabled   = true
      }
    }
  }

  # AWS Managed Rules - Common Rule Set
  dynamic "rule" {
    for_each = var.activate_aws_managed_rules_common ? [1] : []
    content {
      name     = "AWS-AWSManagedRulesCommonRuleSet"
      priority = 10
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = "AWSManagedRulesCommonRuleSet"
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.stack_name}-AWSManagedCommon"
        sampled_requests_enabled   = true
      }
    }
  }

  # AWS Managed Rules - Amazon IP Reputation List
  dynamic "rule" {
    for_each = var.activate_aws_managed_rules_ip_reputation ? [1] : []
    content {
      name     = "AWS-AWSManagedRulesAmazonIpReputationList"
      priority = 20
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = "AWSManagedRulesAmazonIpReputationList"
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.stack_name}-AWSManagedIPReputation"
        sampled_requests_enabled   = true
      }
    }
  }

  # AWS Managed Rules - Anonymous IP List
  dynamic "rule" {
    for_each = var.activate_aws_managed_rules_anonymous_ip ? [1] : []
    content {
      name     = "AWS-AWSManagedRulesAnonymousIpList"
      priority = 30
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          vendor_name = "AWS"
          name        = "AWSManagedRulesAnonymousIpList"
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${var.stack_name}-AWSManagedAnonymousIP"
        sampled_requests_enabled   = true
      }
    }
  }
}

# --- WAF Logging Configuration ---

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count = var.http_flood_protection_log_parser_activated ? 1 : 0

  log_destination_configs = [module.firehose_athena_pipeline.firehose_waf_logs_delivery_stream_arn]
  resource_arn            = aws_wafv2_web_acl.main.arn
}

# Placeholder for S3 buckets
resource "aws_s3_bucket" "waf_log_bucket" {
  bucket = "${lower(var.stack_name)}-waf-logs-${random_uuid.uuid.result}"
}
