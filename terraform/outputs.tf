output "log_parser_lambda_arn" {
  description = "The ARN of the main Log Parser Lambda function."
  value       = aws_lambda_function.log_parser.arn
}

output "firehose_delivery_stream_name" {
  description = "The name of the Kinesis Firehose delivery stream for WAF logs."
  value       = module.firehose_athena_pipeline.firehose_waf_logs_delivery_stream_name
}
