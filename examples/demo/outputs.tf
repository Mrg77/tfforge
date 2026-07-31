output "bucket_id" {
  description = "The ID of the S3 bucket"
  value       = aws_s3_bucket.secure_bucket.id
}

output "bucket_arn" {
  description = "The ARN of the S3 bucket"
  value       = aws_s3_bucket.secure_bucket.arn
}

output "iam_policy_arn" {
  description = "The ARN of the IAM policy for bucket access"
  value       = aws_iam_policy.bucket_access.arn
}

output "iam_role_arn" {
  description = "The ARN of the IAM role for bucket access"
  value       = aws_iam_role.bucket_access_role.arn
}
