variable "environment" {
  description = "Nom de l'environnement"
  type        = string
  default     = "demo"
}

variable "location" {
  description = "Région Azure"
  type        = string
  default     = "swedencentral"
}

variable "jwt_secret" {
  description = "Secret utilisé pour signer les JWT (laisser vide pour en générer un aléatoire)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "token_ttl_seconds" {
  description = "Durée de vie des jetons JWT (secondes)"
  type        = number
  default     = 120
}

variable "hls_segment_seconds" {
  description = "Durée d'un segment HLS (secondes)"
  type        = number
  default     = 6
}
