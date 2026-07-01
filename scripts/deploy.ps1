#!/usr/bin/env pwsh
<#
  Déploiement Zero-Trust HLS — Azure Cloud Shell (PowerShell)
  Aucun Docker, aucun ACR : le code applicatif est packagé en .zip,
  uploadé dans Blob Storage par Terraform, puis téléchargé et lancé
  par le Container App au démarrage (image publique node:20-alpine).
#>

$ErrorActionPreference = "Stop"

$RootDir      = Split-Path -Parent $PSScriptRoot
$KeyserverDir = Join-Path $RootDir "keyserver"
$TerraformDir = Join-Path $RootDir "terraform"
$FilesDir     = Join-Path $TerraformDir "files"
$PackagePath  = Join-Path $FilesDir "app-package.zip"

Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  DEPLOIEMENT ZERO-TRUST HLS (PowerShell / Cloud Shell)"        -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# -------------------------------------------------------------
# [1/4] Vérification de la session Azure
# -------------------------------------------------------------
Write-Host "`n[1/4] Vérification de la connexion Azure" -ForegroundColor Yellow
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "  Vous n'êtes pas connecté. Lancement de 'az login'..." -ForegroundColor Red
    az login | Out-Null
    $account = az account show | ConvertFrom-Json
}
Write-Host "  Abonnement actif : $($account.name) ($($account.id))"

# -------------------------------------------------------------
# [2/4] Packaging du code applicatif (.zip, sans node_modules/Dockerfile)
# -------------------------------------------------------------
Write-Host "`n[2/4] Packaging du Key Server" -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $FilesDir | Out-Null
if (Test-Path $PackagePath) { Remove-Item $PackagePath -Force }

$tempStage = Join-Path ([System.IO.Path]::GetTempPath()) "ztstream-stage"
if (Test-Path $tempStage) { Remove-Item $tempStage -Recurse -Force }
New-Item -ItemType Directory -Path $tempStage | Out-Null

Copy-Item (Join-Path $KeyserverDir "server.js")      $tempStage
Copy-Item (Join-Path $KeyserverDir "package.json")   $tempStage
Copy-Item (Join-Path $KeyserverDir "public") (Join-Path $tempStage "public") -Recurse

Compress-Archive -Path (Join-Path $tempStage "*") -DestinationPath $PackagePath -Force
Remove-Item $tempStage -Recurse -Force
Write-Host "  [OK] Package créé : $PackagePath"

# -------------------------------------------------------------
# [3/4] Déploiement de l'infrastructure (Terraform)
# -------------------------------------------------------------
Write-Host "`n[3/4] Déploiement de l'infrastructure Azure" -ForegroundColor Yellow
Push-Location $TerraformDir
try {
    terraform init -reconfigure
    if ($LASTEXITCODE -ne 0) { throw "terraform init a échoué (code $LASTEXITCODE)" }

    terraform validate
    if ($LASTEXITCODE -ne 0) { throw "terraform validate a échoué (code $LASTEXITCODE)" }

    terraform apply -auto-approve
    if ($LASTEXITCODE -ne 0) { throw "terraform apply a échoué (code $LASTEXITCODE)" }

    $rg            = terraform output -raw resource_group
    $storage       = terraform output -raw storage_account_name
    $keyvault      = terraform output -raw key_vault_name
    $logAnalytics  = terraform output -raw log_analytics_workspace
    $containerApp  = terraform output -raw container_app_name
    $siteUrl       = terraform output -raw site_url
    $adminUser     = terraform output -raw admin_username
    $adminPassword = terraform output -raw admin_password
}
finally {
    Pop-Location
}

Write-Host "`n  [OK] Infrastructure déployée :"
Write-Host "    Resource Group   : $rg"
Write-Host "    Storage Account  : $storage"
Write-Host "    Key Vault        : $keyvault"
Write-Host "    Log Analytics    : $logAnalytics"
Write-Host "    Container App    : $containerApp"
Write-Host "    URL du site      : $siteUrl"

# -------------------------------------------------------------
# [4/4] Attente du démarrage (apk add ffmpeg + npm install au boot)
#       et vérification de santé
# -------------------------------------------------------------
Write-Host "`n[4/4] Vérification du démarrage du Key Server" -ForegroundColor Yellow
$healthUrl = "$siteUrl/healthz"
$maxAttempts = 18
$ok = $false

for ($i = 1; $i -le $maxAttempts; $i++) {
    Start-Sleep -Seconds 10
    try {
        $resp = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -TimeoutSec 8
        if ($resp.StatusCode -eq 200) {
            Write-Host "  [OK] Key Server opérationnel (tentative $i/$maxAttempts)" -ForegroundColor Green
            $ok = $true
            break
        }
    } catch {
        Write-Host "  ... démarrage en cours (tentative $i/$maxAttempts)"
    }
}

if (-not $ok) {
    Write-Host "  [ATTENTION] Le serveur ne répond pas encore. Le premier démarrage" -ForegroundColor Red
    Write-Host "  (téléchargement + 'apk add ffmpeg' + 'npm install') peut prendre 2-3 minutes."
    Write-Host "  Vérifiez les logs avec :"
    Write-Host "    az containerapp logs show --name $containerApp --resource-group $rg --follow"
}

Write-Host "`n════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  DEPLOIEMENT TERMINE"   -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Ouvrez ce lien pour utiliser la console de démo :"
Write-Host "  $siteUrl" -ForegroundColor Green
Write-Host ""
Write-Host "  Compte administrateur créé automatiquement :" -ForegroundColor Yellow
Write-Host "    Identifiant : $adminUser"
Write-Host "    Mot de passe : $adminPassword" -ForegroundColor Green
Write-Host "  (conservez-le : 'terraform output -raw admin_password' pour le retrouver)"
Write-Host ""
Write-Host "  (RBAC peut prendre 1-2 min à se propager : si l'upload échoue"
Write-Host "  juste après le déploiement avec une erreur 403, réessayez.)"
