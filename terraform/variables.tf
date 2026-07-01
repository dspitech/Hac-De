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

variable "admin_username" {
  description = "Identifiant du compte administrateur créé automatiquement au démarrage"
  type        = string
  default     = "admin"
}

variable "session_ttl_seconds" {
  description = "Durée de vie d'un jeton de session (login)"
  type        = number
  default     = 7200
}

variable "guest_ttl_seconds" {
  description = "Durée de vie d'un jeton de session invité (éphémère)"
  type        = number
  default     = 1800
}

variable "download_key_ttl_hours" {
  description = "Durée de validité (heures) d'une clé de déchiffrement d'un téléchargement approuvé"
  type        = number
  default     = 24
}
