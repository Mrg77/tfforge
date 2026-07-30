# A tiny, credential-free Terraform example so tfforge is demoable anywhere.
# It uses the `local` and `random` providers — no cloud account, no secrets —
# yet still produces a real plan/apply/destroy the agent can reason about.

terraform {
  required_version = ">= 1.5"
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

# A random suffix, as a stand-in for a "resource" the agent can plan.
resource "random_pet" "service" {
  length    = 2
  separator = "-"
}

# A generated config file — something apply creates and destroy removes.
resource "local_file" "config" {
  filename = "${path.module}/generated/service.txt"
  content  = "service=${random_pet.service.id}\nenv=staging\n"
}

output "service_name" {
  value = random_pet.service.id
}
