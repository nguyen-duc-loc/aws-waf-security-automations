variable "aws_region" {
  description = "The AWS region to deploy resources in."
  type        = string
}

variable "stack_name" {
  description = "A name for the stack, used to prefix resource names."
  type        = string
  default     = "WAF-Security-Automations"
}

variable "scope" {
  description = "The scope of the WAFv2 resources, either REGIONAL or CLOUDFRONT."
  type        = string
  default     = "REGIONAL"
}

variable "log_type" {
  description = "The type of logs to process, either ALB or CLOUDFRONT."
  type        = string
  default     = "ALB"
}

variable "app_access_log_bucket" {
  description = "The name of the S3 bucket for application access logs."
  type        = string
}

variable "http_flood_protection_log_parser_activated" {
  description = "Flag to activate HTTP Flood Protection using a log parser."
  type        = bool
  default     = true
}

variable "athena_log_parser_activated" {
  description = "Flag to activate the Athena Log Parser feature."
  type        = bool
  default     = true
}

variable "http_flood_lambda_log_parser_activated" {
  description = "Flag to activate the HTTP Flood detection feature using Lambda log parsing."
  type        = bool
  default     = false # Default to Athena mode as per original logic
}

variable "http_flood_athena_log_parser_activated" {
  description = "Flag to activate the HTTP Flood detection feature using Athena."
  type        = bool
  default     = true
}

variable "scanners_probes_athena_log_parser_activated" {
  description = "Flag to activate the Scanners & Probes detection feature using Athena."
  type        = bool
  default     = false
}

variable "alb_scanners_probes_athena_log_parser_activated" {
  description = "Flag to activate the Scanners & Probes detection for ALB logs."
  type        = bool
  default     = false
}

variable "cloudfront_scanners_probes_athena_log_parser_activated" {
  description = "Flag to activate the Scanners & Probes detection for CloudFront logs."
  type        = bool
  default     = false
}

# --- WAF WebACL Rule Activation Flags ---

variable "activate_aws_managed_rules_common" {
  description = "Activate AWS Managed Rules Common Rule Set (CRS)."
  type        = bool
  default     = true
}

variable "activate_aws_managed_rules_ip_reputation" {
  description = "Activate AWS Managed Rules Amazon IP Reputation List."
  type        = bool
  default     = true
}

variable "activate_aws_managed_rules_anonymous_ip" {
  description = "Activate AWS Managed Rules Anonymous IP List."
  type        = bool
  default     = true
}

variable "activate_sql_injection_protection" {
  description = "Activate custom SQL Injection Protection rule."
  type        = bool
  default     = true
}

variable "activate_xss_protection" {
  description = "Activate custom Cross-Site Scripting (XSS) Protection rule."
  type        = bool
  default     = true
}

variable "request_threshold" {
  description = "Request threshold for rate-based rules."
  type        = number
  default     = 100
}
