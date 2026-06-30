#!/usr/bin/env pwsh
<#
  Démonstration / vérification Zero-Trust HLS
#>

$ErrorActionPreference = "Stop"
$RootDir      = Split-Path -Parent $PSScriptRoot
$TerraformDir = Join-Path $RootDir "terraform"

Push-Location $TerraformDir
$rg          = terraform output -raw resource_group
$storage     = terraform output -raw storage_account_name
$keyvault    = terraform output -raw key_vault_name
$siteUrl     = terraform output -raw site_url
Pop-Location

Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  DEMONSTRATION ZERO-TRUST HLS"
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`n[1] Infrastructure"
Write-Host "  Resource Group  : $rg"
Write-Host "  Storage Account : $storage"
Write-Host "  Key Vault       : $keyvault"
Write-Host "  Site            : $siteUrl"

Write-Host "`n[2] Health check"
$health = Invoke-RestMethod -Uri "$siteUrl/healthz"
Write-Host "  $($health | ConvertTo-Json -Compress)"

Write-Host "`n[3] Vidéos déjà disponibles (Storage)"
try {
    $videos = Invoke-RestMethod -Uri "$siteUrl/videos"
    if ($videos.videos.Count -eq 0) {
        Write-Host "  Aucune vidéo pour l'instant. Utilisez le site web pour en téléverser une :"
        Write-Host "  $siteUrl"
    } else {
        $videos.videos | ForEach-Object { Write-Host "  - $($_.title)  [$($_.videoId)]" }
    }
} catch {
    Write-Host "  Impossible de lister les vidéos : $_"
}

Write-Host "`n[4] Test Zero-Trust : accès à une clé SANS jeton (doit être refusé)"
try {
    Invoke-WebRequest -Uri "$siteUrl/keys/inexistant" -UseBasicParsing | Out-Null
    Write-Host "  [ATTENTION] La requête n'a pas été refusée comme attendu"
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 401) {
        Write-Host "  [OK] HTTP 401 - accès refusé sans jeton JWT (Zero-Trust validé)" -ForegroundColor Green
    } else {
        Write-Host "  HTTP $code reçu"
    }
}

Write-Host "`n[5] Génération d'un jeton de test"
$tokenResp = Invoke-RestMethod -Method Post -Uri "$siteUrl/auth/token" `
    -ContentType "application/json" -Body (@{ videoId = "demo" } | ConvertTo-Json)
Write-Host "  Jeton (tronqué) : $($tokenResp.access_token.Substring(0, [Math]::Min(40, $tokenResp.access_token.Length)))..."

Write-Host "`n════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Ouvrez $siteUrl dans un navigateur pour la démo complète" -ForegroundColor Green
Write-Host "  (upload -> segmentation -> chiffrement -> lecture protégée)"
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
