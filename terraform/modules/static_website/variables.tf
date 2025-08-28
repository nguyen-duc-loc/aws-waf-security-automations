variable "bucket_name" {
  description = "The name of the S3 bucket. Must be globally unique."
  type        = string
}

variable "index_document" {
  description = "The name of the index document for the website."
  type        = string
  default     = "index.html"
}

variable "error_document" {
  description = "The name of the error document for the website."
  type        = string
  default     = "error.html"
}

variable "tags" {
  description = "A map of tags to assign to the resources."
  type        = map(string)
  default     = {}
}
