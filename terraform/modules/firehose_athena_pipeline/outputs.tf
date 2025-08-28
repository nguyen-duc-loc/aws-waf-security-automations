
output "firehose_waf_logs_delivery_stream_arn" {
  description = "The ARN of the Firehose WAF Logs Delivery Stream."
  value       = try(aws_kinesis_firehose_delivery_stream.firehose_waf_logs_delivery_stream[0].arn, null)
}

output "glue_access_logs_database_name" {
  description = "The name of the Glue Access Logs Database."
  value       = try(aws_glue_catalog_database.glue_access_logs_database[0].name, null)
}

output "glue_waf_access_logs_table_name" {
  description = "The name of the Glue WAF Access Logs Table."
  value       = try(aws_glue_catalog_table.glue_waf_access_logs_table[0].name, null)
}

output "glue_app_access_logs_table_name" {
  description = "The name of the Glue App Access Logs Table."
  value       = var.alb_scanners_probes_athena_log_parser_activated ? try(aws_glue_catalog_table.alb_glue_app_access_logs_table[0].name, null) : try(aws_glue_catalog_table.cloudfront_glue_app_access_logs_table[0].name, null)
}

output "waf_add_partition_athena_query_workgroup_name" {
  description = "The name of the WAF Add Partition Athena Query WorkGroup."
  value       = try(aws_athena_workgroup.waf_add_partition_workgroup[0].name, null)
}

output "waf_log_athena_query_workgroup_name" {
  description = "The name of the WAF Log Athena Query WorkGroup."
  value       = try(aws_athena_workgroup.waf_log_query_workgroup[0].name, null)
}

output "waf_app_access_log_athena_query_workgroup_name" {
  description = "The name of the WAF App Access Log Athena Query WorkGroup."
  value       = try(aws_athena_workgroup.waf_app_access_log_query_workgroup[0].name, null)
}
