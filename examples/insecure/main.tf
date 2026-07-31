# DELIBERATELY INSECURE — a demo target for tfforge's scan + auto-correct loop.
# This is what a rushed, unsafe Terraform file looks like. Ask tfforge to
# "scan ./examples/insecure and fix every security finding" to watch it
# rewrite this into something safe.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# A public bucket with no encryption — several problems at once.
resource "aws_s3_bucket" "data" {
  bucket = "my-company-data"
  acl    = "public-read"
}

# An IAM policy that grants everything to everyone — the classic anti-pattern.
resource "aws_iam_policy" "admin" {
  name = "app-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
