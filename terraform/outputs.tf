output "resource_group" {
  value = azurerm_resource_group.main.name
}

output "acr_login_server" {
  value = azurerm_container_registry.main.login_server
}

output "acr_name" {
  value = azurerm_container_registry.main.name
}

output "key_server_fqdn" {
  value = "https://${azurerm_container_app.keyserver.ingress[0].fqdn}"
}

output "storage_account_name" {
  value = azurerm_storage_account.main.name
}

output "storage_container_hls" {
  value = azurerm_storage_container.hls.name
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

output "keyserver_identity_client_id" {
  value = azurerm_user_assigned_identity.keyserver.client_id
}
