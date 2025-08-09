terraform {
  required_version = ">= 1.0"
  
  required_providers {
    kafka-connect = {
      source  = "Mongey/kafka-connect"
      version = "~> 0.2.4"
    }
  }
}
