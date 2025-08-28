
variable "http_flood_protection_log_parser_activated" {
  description = "Flag to activate HTTP Flood Protection Log Parser."
  type        = bool
  default     = false
}

variable "athena_log_parser_activated" {
  description = "Flag to activate Athena Log Parser."
  type        = bool
  default     = false
}

variable "http_flood_athena_log_parser_activated" {
  description = "Flag to activate HTTP Flood Athena Log Parser."
  type        = bool
  default     = false
}

variable "scanners_probes_athena_log_parser_activated" {
  description = "Flag to activate Scanners/Probes Athena Log Parser."
  type        = bool
  default     = false
}

variable "alb_scanners_probes_athena_log_parser_activated" {
  description = "Flag to activate ALB Scanners/Probes Athena Log Parser."
  type        = bool
  default     = false
}

variable "cloudfront_scanners_probes_athena_log_parser_activated" {
  description = "Flag to activate CloudFront Scanners/Probes Athena Log Parser."
  type        = bool
  default     = false
}

variable "parent_stack_name" {
  description = "The name of the parent stack."
  type        = string
}

variable "aws_account_id" {
  description = "The AWS account ID."
  type        = string
}

variable "aws_partition" {
  description = "The AWS partition (e.g., 'aws', 'aws-cn')."
  type        = string
  default     = "aws"
}

variable "aws_region" {
  description = "The AWS region."
  type        = string
}

variable "waf_log_bucket_arn" {
  description = "The ARN of the WAF log bucket."
  type        = string
}

variable "waf_log_bucket_name" {
  description = "The name of the WAF log bucket."
  type        = string
}

variable "delivery_stream_name" {
  description = "The name of the Kinesis Firehose delivery stream."
  type        = string
}

variable "glue_database_name" {
  description = "The name of the Glue database."
  type        = string
}

variable "app_access_log_bucket" {
  description = "The name of the application access log bucket."
  type        = string
}

variable "uuid" {
  description = "A unique identifier for resource naming."
  type        = string
}
