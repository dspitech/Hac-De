variable "project_name" {
  description = "Préfixe utilisé pour nommer toutes les ressources"
  type        = string
  default     = "ztstream"
}

variable "location" {
  description = "Région Azure"
  type        = string
  default     = "swedencentral"
}

variable "environment" {
  description = "Nom de l'environnement (dev, demo, prod)"
  type        = string
  default     = "demo"
}

variable "jwt_signing_secret" {
  description = "Secret utilisé par le Key Server pour vérifier les JWT (HS256). Si vide, un secret aléatoire est généré."
  type        = string
  default     = ""
  sensitive   = true
}

variable "key_server_image" {
  description = "Image complète du Key Server dans l'ACR (rempli après le premier build, ex: <acr>.azurecr.io/keyserver:latest)"
  type        = string
  default     = ""
}

variable "container_cpu" {
  type    = number
  default = 0.5
}

variable "container_memory" {
  type    = string
  default = "1Gi"
}

variable "allowed_origins" {
  description = "Origines CORS autorisées pour le Key Server (lecteur HLS)"
  type        = list(string)
  default     = ["*"]
}
