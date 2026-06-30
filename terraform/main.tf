############################################
# Naming & randomisation pour unicité globale
############################################
resource "random_string" "suffix" {
  length  = 5
  special = false
  upper   = false
}

resource "random_password" "jwt_secret" {
  count   = var.jwt_signing_secret == "" ? 1 : 0
  length  = 48
  special = false
}

locals {
  suffix      = random_string.suffix.result
  name_prefix = "${var.project_name}-${var.environment}"
  jwt_secret  = var.jwt_signing_secret != "" ? var.jwt_signing_secret : random_password.jwt_secret[0].result
}

############################################
# Resource Group
############################################
resource "azurerm_resource_group" "main" {
  name     = "rg-${local.name_prefix}"
  location = var.location
}

############################################
# Log Analytics (requis par Container Apps Env)
############################################
resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${local.name_prefix}-${local.suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
}

############################################
# Azure Container Registry (images Key Server)
# Zero-Trust: pas d'admin user, pull via Managed Identity + RBAC
############################################
resource "azurerm_container_registry" "main" {
  name                = "acr${replace(local.name_prefix, "-", "")}${local.suffix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = false
}

############################################
# Key Vault: stocke le secret JWT et la clé maître AES
# Zero-Trust: accès uniquement via Managed Identity + RBAC, pas de clé d'accès partagée
############################################
data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                       = "kv-${substr(local.name_prefix, 0, 10)}-${local.suffix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  enable_rbac_authorization  = true
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
}

# L'utilisateur courant (vous, via Cloud Shell) reçoit le droit d'écrire des secrets
resource "azurerm_role_assignment" "kv_admin_current_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_secret" "jwt_secret" {
  name         = "jwt-signing-secret"
  value        = local.jwt_secret
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_role_assignment.kv_admin_current_user]
}

############################################
# Storage Account: segments HLS chiffrés
# Zero-Trust: accès public désactivé, lecture via SAS de courte durée uniquement
############################################
resource "azurerm_storage_account" "main" {
  name                            = "st${replace(local.name_prefix, "-", "")}${local.suffix}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_container" "hls" {
  name                  = "hls-segments"
  storage_account_name  = azurerm_storage_account.main.name
  container_access_type = "private"
}

############################################
# Container Apps Environment
############################################
resource "azurerm_container_app_environment" "main" {
  name                       = "cae-${local.name_prefix}-${local.suffix}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
}

############################################
# Container App: Key Server
# Zero-Trust: Identité managée system-assigned, secrets injectés depuis Key Vault,
# JWT requis pour toute délivrance de clé AES, HTTPS forcé (ingress externe TLS).
############################################
resource "azurerm_user_assigned_identity" "keyserver" {
  name                = "id-keyserver-${local.suffix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

# Droit de pull d'images sur l'ACR (RBAC, pas de mot de passe)
resource "azurerm_role_assignment" "acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.keyserver.principal_id
}

# Droit de lire les secrets du Key Vault
resource "azurerm_role_assignment" "kv_reader_keyserver" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.keyserver.principal_id
}

resource "azurerm_container_app" "keyserver" {
  name                         = "ca-keyserver-${local.suffix}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.keyserver.id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.keyserver.id
  }

  secret {
    name                = "jwt-secret"
    key_vault_secret_id = azurerm_key_vault_secret.jwt_secret.id
    identity            = azurerm_user_assigned_identity.keyserver.id
  }

  template {
    min_replicas = 1
    max_replicas = 2

    container {
      name   = "keyserver"
      # NB: tant que l'image n'a pas été buildée/poussée dans l'ACR,
      # on démarre sur une image placeholder publique pour que le déploiement Terraform réussisse.
      image  = var.key_server_image != "" ? var.key_server_image : "mcr.microsoft.com/azuredocs/containerapps-helloworld:latest"
      cpu    = var.container_cpu
      memory = var.container_memory

      env {
        name        = "JWT_SECRET"
        secret_name = "jwt-secret"
      }
      env {
        name  = "ALLOWED_ORIGINS"
        value = join(",", var.allowed_origins)
      }
      env {
        name  = "NODE_ENV"
        value = "production"
      }
    }
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

  lifecycle {
    ignore_changes = [
      template[0].container[0].image,
    ]
  }
}
