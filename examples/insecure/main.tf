terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Random suffix for unique bucket name
resource "random_id" "suffix" {
  byte_length = 4
}

# S3 bucket - now private and secure
resource "aws_s3_bucket" "data" {
  bucket = "example-insecure-bucket-${random_id.suffix.hex}"

  tags = {
    Name        = "SecureDataBucket"
    Environment = "Production"
  }
}

# Block all public access to the bucket
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable server-side encryption with AES256
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

# Set private ACL using the dedicated resource
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "private"

  depends_on = [aws_s3_bucket_public_access_block.data]
}

# IAM policy - scoped to specific actions and resources
resource "aws_iam_policy" "admin" {
  name        = "scoped-s3-policy"
  description = "Scoped policy for S3 operations on specific bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadWriteAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
      },
      {
        Sid    = "S3BucketLocationAccess"
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:ListAllMyBuckets"
        ]
        Resource = "arn:aws:s3:::*"
      }
    ]
  })
}
