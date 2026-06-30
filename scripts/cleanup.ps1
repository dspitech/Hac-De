#!/usr/bin/env pwsh
<#
  Nettoyage des ressources Azure (suppression du Resource Group)
#>

$ErrorActionPreference = "Stop"
$RootDir      = Split-Path -Parent $PSScriptRoot
$TerraformDir = Join-Path $RootDir "terraform"

Push-Location $TerraformDir
try {
    $rg = terraform output -raw resource_group 2>$null
} catch {
    $rg = "rg-ztstream-demo"
}
Pop-Location

if (-not $rg) { $rg = "rg-ztstream-demo" }

Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  NETTOYAGE DES RESSOURCES"
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "`n  Suppression du resource group : $rg"

az group delete --name $rg --yes --no-wait

Write-Host "`n  [OK] Suppression lancée (asynchrone, quelques minutes)."
Write-Host "  Vérifiez avec : az group exists --name $rg"
