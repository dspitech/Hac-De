output "resource_group" {
  value = azurerm_resource_group.main.name
}

output "storage_account_name" {
  value = azurerm_storage_account.main.name
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

output "log_analytics_workspace" {
  value = azurerm_log_analytics_workspace.main.name
}

output "container_app_name" {
  value = azurerm_container_app.keyserver.name
}

output "key_server_fqdn" {
  value = azurerm_container_app.keyserver.ingress[0].fqdn
}

output "site_url" {
  value = "https://${azurerm_container_app.keyserver.ingress[0].fqdn}"
}

output "admin_username" {
  value = var.admin_username
}

output "admin_password" {
  value     = random_password.admin_password.result
  sensitive = true
}

output "application_insights_name" {
  value = azurerm_application_insights.main.name
}
