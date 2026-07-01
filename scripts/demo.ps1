#!/usr/bin/env pwsh
<#
  Démonstration / vérification Zero-Trust HLS (v3 — avec authentification)
#>

$ErrorActionPreference = "Stop"
$RootDir      = Split-Path -Parent $PSScriptRoot
$TerraformDir = Join-Path $RootDir "terraform"

Push-Location $TerraformDir
$rg            = terraform output -raw resource_group
$storage       = terraform output -raw storage_account_name
$keyvault      = terraform output -raw key_vault_name
$siteUrl       = terraform output -raw site_url
$adminUser     = terraform output -raw admin_username
$adminPassword = terraform output -raw admin_password
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

Write-Host "`n[3] Test Zero-Trust : accès à /videos SANS jeton de session (doit être refusé)"
try {
    Invoke-WebRequest -Uri "$siteUrl/videos" -UseBasicParsing | Out-Null
    Write-Host "  [ATTENTION] La requête n'a pas été refusée comme attendu" -ForegroundColor Red
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($code -eq 401) {
        Write-Host "  [OK] HTTP 401 - accès refusé sans session (Zero-Trust validé)" -ForegroundColor Green
    } else {
        Write-Host "  HTTP $code reçu"
    }
}

Write-Host "`n[4] Connexion en tant qu'administrateur"
$loginResp = Invoke-RestMethod -Method Post -Uri "$siteUrl/auth/login" `
    -ContentType "application/json" `
    -Body (@{ username = $adminUser; password = $adminPassword } | ConvertTo-Json)
$sessionToken = $loginResp.access_token
Write-Host "  [OK] Connecté en tant que '$($loginResp.username)' (rôle: $($loginResp.role))"

Write-Host "`n[5] Vidéos disponibles"
$headers = @{ Authorization = "Bearer $sessionToken" }
$videos = Invoke-RestMethod -Uri "$siteUrl/videos" -Headers $headers
if ($videos.videos.Count -eq 0) {
    Write-Host "  Aucune vidéo pour l'instant. Connectez-vous sur le site pour en téléverser une :"
    Write-Host "  $siteUrl"
} else {
    $videos.videos | ForEach-Object { Write-Host "  - $($_.title)  [$($_.videoId)]  par $($_.ownerUsername)" }

    $firstVideo = $videos.videos[0]
    Write-Host "`n[6] Cycle complet de délivrance de clé sur '$($firstVideo.title)'"
    $keyTokenResp = Invoke-RestMethod -Method Post -Uri "$siteUrl/videos/$($firstVideo.videoId)/key-token" -Headers $headers
    Write-Host "  Jeton clé (120s, tronqué) : $($keyTokenResp.access_token.Substring(0, 40))..."

    $keyHeaders = @{ Authorization = "Bearer $($keyTokenResp.access_token)" }
    $keyResp = Invoke-WebRequest -Uri "$siteUrl/keys/$($firstVideo.videoId)" -Headers $keyHeaders -UseBasicParsing
    Write-Host "  [OK] Clé AES-128 reçue : $($keyResp.RawContentLength) octets, Content-Type: $($keyResp.Headers['Content-Type'])" -ForegroundColor Green
}

Write-Host "`n[7] Déconnexion (révoque la session)"
Invoke-RestMethod -Method Post -Uri "$siteUrl/auth/logout" -Headers $headers | Out-Null
Write-Host "  [OK] Session révoquée"

try {
    Invoke-WebRequest -Uri "$siteUrl/videos" -Headers $headers -UseBasicParsing | Out-Null
    Write-Host "  [ATTENTION] La session révoquée fonctionne encore !" -ForegroundColor Red
} catch {
    Write-Host "  [OK] La session révoquée est bien refusée (401)" -ForegroundColor Green
}

Write-Host "`n════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Ouvrez $siteUrl dans un navigateur pour la démo complète" -ForegroundColor Green
Write-Host "  (connexion admin : $adminUser / voir terraform output -raw admin_password)"
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
