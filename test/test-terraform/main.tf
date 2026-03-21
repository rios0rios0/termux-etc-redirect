terraform {
  required_providers {
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
  }
}

data "http" "test" {
  url = "https://api.github.com/zen"
}

output "response" {
  value = data.http.test.response_body
}
