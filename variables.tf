variable "db_username" {
  description = "Username para RDS"
  type        = string
}

variable "db_password" {
  description = "Password para RDS"
  type        = string
  sensitive   = true  # Marca la variable como sensible para ocultar su valor
}
