terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.110"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
  }
}

data "azurerm_client_config" "current" {}

resource "random_integer" "suffix" {
  min = 1000
  max = 9999
}

resource "random_password" "jwt_secret" {
  count   = var.jwt_secret == "" ? 1 : 0
  length  = 48
  special = false
}

resource "random_password" "admin_password" {
  length  = 16
  special = true
  override_special = "-_!#%"
}

locals {
  jwt_secret      = var.jwt_secret != "" ? var.jwt_secret : random_password.jwt_secret[0].result
  uploads_container = "uploads"
  hls_container      = "hls-segments"
  appcode_container  = "app-code"
  downloads_container = "downloads"
  app_package_path   = "${path.module}/files/app-package.zip"
}

# ============================================================
# RESOURCE GROUP
# ============================================================
resource "azurerm_resource_group" "main" {
  name     = "rg-ztstream-demo"
  location = var.location
  tags = {
    Environment = var.environment
    Project     = "ZeroTrust-Streaming"
    ManagedBy   = "Terraform"
  }
}

# ============================================================
# LOG ANALYTICS (analytique pour Container Apps, Storage, Key Vault)
# ============================================================
resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-ztstream-${random_integer.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

# ============================================================
# STORAGE ACCOUNT (vidéos brutes + segments HLS + code applicatif)
# ============================================================
resource "azurerm_storage_account" "main" {
  name                            = "stzt${random_integer.suffix.result}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = true # nécessaire pour la lecture publique des segments chiffrés

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 7
    }
  }

  tags = azurerm_resource_group.main.tags
}

# Segments HLS chiffrés + playlists : lecture publique (le contenu est chiffré,
# seule la clé AES est protégée par JWT)
resource "azurerm_storage_container" "hls" {
  name                  = local.hls_container
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "blob"
}

# Vidéos sources brutes : privé, jamais exposé publiquement
resource "azurerm_storage_container" "uploads" {
  name                  = local.uploads_container
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

# Exports chiffrés générés pour les téléchargements approuvés : privé,
# clé de déchiffrement séparée des clés de streaming, à durée de vie limitée
resource "azurerm_storage_container" "downloads" {
  name                  = local.downloads_container
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

# Code applicatif du Key Server (pas de secret dedans), servi en lecture
# publique pour que le Container App puisse le télécharger au démarrage
# sans dépendre d'un registre de conteneurs (ACR).
resource "azurerm_storage_container" "appcode" {
  name                  = local.appcode_container
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "blob"
}

resource "azurerm_storage_blob" "app_package" {
  name                   = "app-package.zip"
  storage_account_name   = azurerm_storage_account.main.name
  storage_container_name = azurerm_storage_container.appcode.name
  type                    = "Block"
  source                  = local.app_package_path
  content_md5             = filemd5(local.app_package_path)
}

# ============================================================
# TABLES (comptes utilisateurs, commentaires, révocation de
# jetons, journal d'audit) — accès exclusivement via identité
# managée (RBAC "Storage Table Data Contributor"), pas de clé
# de compte de stockage.
# ============================================================
resource "azurerm_storage_table" "users" {
  name                 = "Users"
  storage_account_name = azurerm_storage_account.main.name
}

resource "azurerm_storage_table" "comments" {
  name                 = "Comments"
  storage_account_name = azurerm_storage_account.main.name
}

resource "azurerm_storage_table" "revoked_tokens" {
  name                 = "RevokedTokens"
  storage_account_name = azurerm_storage_account.main.name
}

resource "azurerm_storage_table" "audit_log" {
  name                 = "AuditLog"
  storage_account_name = azurerm_storage_account.main.name
}

resource "azurerm_storage_table" "download_requests" {
  name                 = "DownloadRequests"
  storage_account_name = azurerm_storage_account.main.name
}

# Diagnostic settings -> Log Analytics (couche "analytique")
resource "azurerm_monitor_diagnostic_setting" "storage_blob_diag" {
  name                       = "diag-blob-${random_integer.suffix.result}"
  target_resource_id        = "${azurerm_storage_account.main.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }
  metric {
    category = "Transaction"
    enabled  = true
  }
}

# ============================================================
# APPLICATION INSIGHTS (traces de requêtes, dépendances,
# événements custom de login/upload/délivrance de clé) —
# alimente le même workspace Log Analytics que le reste.
# ============================================================
resource "azurerm_application_insights" "main" {
  name                = "appi-ztstream-${random_integer.suffix.result}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "Node.JS"
}

# ============================================================
# KEY VAULT (clés AES-128, une par vidéo) — autorisation par RBAC
# ============================================================
resource "azurerm_key_vault" "main" {
  name                       = "kv-zt${random_integer.suffix.result}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  enable_rbac_authorization  = true

  tags = azurerm_resource_group.main.tags
}

resource "azurerm_monitor_diagnostic_setting" "kv_diag" {
  name                       = "diag-kv-${random_integer.suffix.result}"
  target_resource_id        = azurerm_key_vault.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AuditEvent"
  }
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# Permet à l'utilisateur courant (vous, dans Cloud Shell) de gérer les
# secrets pour le débogage / la démo (az keyvault secret ...)
resource "azurerm_role_assignment" "current_user_kv" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id          = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "current_user_tables" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Table Data Contributor"
  principal_id          = data.azurerm_client_config.current.object_id
}

# Lecture seule sur les blobs pour l'utilisateur courant (Cloud Shell) —
# utilisé uniquement par scripts/verify-encryption.ps1 pour lister les
# vidéos disponibles, jamais pour contourner le Key Server
resource "azurerm_role_assignment" "current_user_blob_reader" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Reader"
  principal_id          = data.azurerm_client_config.current.object_id
}

# ============================================================
# CONTAINER APPS ENVIRONMENT (relié à Log Analytics)
# ============================================================
resource "azurerm_container_app_environment" "main" {
  name                       = "cae-zt-${random_integer.suffix.result}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
}

# ============================================================
# CONTAINER APP (Key Server) — image publique node:20-alpine,
# le code applicatif est téléchargé au démarrage depuis le Storage
# (aucune image personnalisée, donc aucun ACR nécessaire)
# ============================================================
resource "azurerm_container_app" "keyserver" {
  name                         = "ca-keyserver-${random_integer.suffix.result}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  identity {
    type = "SystemAssigned"
  }

  template {
    min_replicas = 1
    max_replicas = 2

    container {
      name   = "keyserver"
      image  = "docker.io/library/node:20-alpine"
      cpu    = 0.5
      memory = "1Gi"

      command = ["sh", "-c"]
      args = [
        <<-EOT
        set -e
        apk add --no-cache ffmpeg curl unzip >/dev/null
        mkdir -p /app
        curl -fsSL "$APP_PACKAGE_URL" -o /tmp/app.zip
        unzip -q /tmp/app.zip -d /app
        cd /app
        npm install --omit=dev --no-audit --no-fund
        exec node server.js
        EOT
      ]

      env {
        name  = "APP_PACKAGE_URL"
        value = "${azurerm_storage_account.main.primary_blob_endpoint}${local.appcode_container}/app-package.zip"
      }
      env {
        name  = "PORT"
        value = "8080"
      }
      env {
        name        = "JWT_SECRET"
        secret_name = "jwt-secret"
      }
      env {
        name  = "TOKEN_TTL_SECONDS"
        value = tostring(var.token_ttl_seconds)
      }
      env {
        name  = "SESSION_TTL_SECONDS"
        value = tostring(var.session_ttl_seconds)
      }
      env {
        name  = "GUEST_TTL_SECONDS"
        value = tostring(var.guest_ttl_seconds)
      }
      env {
        name  = "HLS_SEGMENT_SECONDS"
        value = tostring(var.hls_segment_seconds)
      }
      env {
        name  = "STORAGE_ACCOUNT_NAME"
        value = azurerm_storage_account.main.name
      }
      env {
        name  = "UPLOADS_CONTAINER"
        value = local.uploads_container
      }
      env {
        name  = "HLS_CONTAINER"
        value = local.hls_container
      }
      env {
        name  = "DOWNLOAD_CONTAINER"
        value = local.downloads_container
      }
      env {
        name  = "DOWNLOAD_KEY_TTL_HOURS"
        value = tostring(var.download_key_ttl_hours)
      }
      env {
        name  = "KEYVAULT_URI"
        value = azurerm_key_vault.main.vault_uri
      }
      env {
        name  = "ALLOWED_ORIGINS"
        value = "*"
      }
      env {
        name  = "NODE_ENV"
        value = "production"
      }
      env {
        name  = "ADMIN_USERNAME"
        value = var.admin_username
      }
      env {
        name        = "ADMIN_PASSWORD"
        secret_name = "admin-password"
      }
      env {
        name  = "APPLICATIONINSIGHTS_CONNECTION_STRING"
        value = azurerm_application_insights.main.connection_string
      }
    }
  }

  secret {
    name  = "jwt-secret"
    value = local.jwt_secret
  }
  secret {
    name  = "admin-password"
    value = random_password.admin_password.result
  }

  ingress {
    external_enabled = true
    target_port       = 8080
    transport         = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}

# Identité managée du Container App -> droits sur Storage (lecture/écriture blobs)
resource "azurerm_role_assignment" "containerapp_storage" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id          = azurerm_container_app.keyserver.identity[0].principal_id
}

# Identité managée du Container App -> droits sur Key Vault (lire/écrire les clés)
resource "azurerm_role_assignment" "containerapp_kv" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id          = azurerm_container_app.keyserver.identity[0].principal_id
}

# Identité managée du Container App -> droits sur les Tables (utilisateurs,
# commentaires, jetons révoqués, journal d'audit)
resource "azurerm_role_assignment" "containerapp_tables" {
  scope                = azurerm_storage_account.main.id
  role_definition_name = "Storage Table Data Contributor"
  principal_id          = azurerm_container_app.keyserver.identity[0].principal_id
}
