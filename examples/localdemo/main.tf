terraform {
  required_version = ">= 1.0"
  required_providers {
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
  }
}

# Generate a random pet name
resource "random_pet" "demo" {
  length    = 3
  separator = "-"
}

# Create a local file with the pet name
resource "local_file" "pet_file" {
  filename = "${path.module}/pet-name.txt"
  content  = "Your random pet name is: ${random_pet.demo.id}\n"
  file_permission = "0644"
}
