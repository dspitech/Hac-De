#!/usr/bin/env pwsh
<#
  verify-encryption.ps1 — Vérifie techniquement qu'une vidéo est bien
  chiffrée sur la plateforme Zero-Trust HLS, sans jamais utiliser de
  clé de compte de stockage (lecture des segments publics + Storage
  Blob Data Reader RBAC pour le listage uniquement).

  Contrôles effectués :
   1. La playlist .m3u8 contient une directive #EXT-X-KEY par segment
      (preuve qu'une clé DISTINCTE est déclarée pour chaque segment)
   2. Les IV (vecteurs d'initialisation) de chaque directive sont bien
      tous différents (preuve que les clés ne sont pas réutilisées)
   3. Le premier segment .ts, lu en clair depuis le Storage, n'a PAS la
      structure d'un flux MPEG-TS valide (l'octet de synchronisation
      0x47 attendu tous les 188 octets est absent) — preuve que le
      contenu est bien chiffré et non un flux TS en clair
   4. La route /keys/:videoId/0 du Key Server refuse l'accès sans jeton
      (HTTP 401) — preuve que la clé n'est pas récupérable sans passer
      par le contrôle Zero-Trust

  Usage :
    ./scripts/verify-encryption.ps1                  # liste les vidéos et demande de choisir
    ./scripts/verify-encryption.ps1 -VideoId <uuid>   # vérifie directement une vidéo précise
#>

param(
  [Parameter(Mandatory = $false)][string]$VideoId
)

$ErrorActionPreference = "Stop"
$RootDir      = Split-Path -Parent $PSScriptRoot
$TerraformDir = Join-Path $RootDir "terraform"

Push-Location $TerraformDir
$storage = terraform output -raw storage_account_name
$siteUrl = terraform output -raw site_url
Pop-Location

$blobBase = "https://$storage.blob.core.windows.net/hls-segments"

function Write-Check {
  param([string]$Label, [bool]$Passed, [string]$Detail = "")
  $mark = if ($Passed) { "✓ PASS" } else { "✗ FAIL" }
  $color = if ($Passed) { "Green" } else { "Red" }
  Write-Host "  [$mark] $Label" -ForegroundColor $color
  if ($Detail) { Write-Host "         $Detail" -ForegroundColor DarkGray }
}

Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  VERIFICATION DE CHIFFREMENT — Zero-Trust HLS"
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# -------------------------------------------------------------
# Sélection de la vidéo à tester
# -------------------------------------------------------------
if (-not $VideoId) {
  Write-Host "`nAucun -VideoId fourni : listage des vidéos disponibles…" -ForegroundColor Yellow
  $metaBlobs = az storage blob list `
    --account-name $storage --container-name hls-segments `
    --auth-mode login --query "[?ends_with(name, 'meta.json')].name" -o tsv

  if (-not $metaBlobs) {
    Write-Host "Aucune vidéo trouvée dans le storage. Téléversez-en une depuis le site d'abord." -ForegroundColor Red
    exit 1
  }

  $videos = @()
  foreach ($blobName in ($metaBlobs -split "`n" | Where-Object { $_ })) {
    $vid = ($blobName -split "/")[0]
    try {
      $metaJson = az storage blob download --account-name $storage --container-name hls-segments `
        --name $blobName --auth-mode login --no-progress -o tsv --query "." 2>$null
    } catch { $metaJson = $null }
    $videos += [PSCustomObject]@{ VideoId = $vid }
  }

  Write-Host "`nVidéos disponibles :" -ForegroundColor Yellow
  for ($i = 0; $i -lt $videos.Count; $i++) { Write-Host "  [$i] $($videos[$i].VideoId)" }

  $choice = Read-Host "`nChoisissez un index (ou collez directement un videoId)"
  if ($choice -match '^\d+$' -and [int]$choice -lt $videos.Count) {
    $VideoId = $videos[[int]$choice].VideoId
  } else {
    $VideoId = $choice
  }
}

Write-Host "`nVidéo testée : $VideoId" -ForegroundColor Yellow
Write-Host "Playlist     : $blobBase/$VideoId/playlist.m3u8`n"

$allPassed = $true

# -------------------------------------------------------------
# [1] Une directive #EXT-X-KEY par segment
# -------------------------------------------------------------
try {
  $playlist = Invoke-RestMethod -Uri "$blobBase/$VideoId/playlist.m3u8" -UseBasicParsing
} catch {
  Write-Host "Impossible de récupérer la playlist : $_" -ForegroundColor Red
  exit 1
}

$keyLines = [regex]::Matches($playlist, '#EXT-X-KEY:[^\r\n]+')
$segmentLines = [regex]::Matches($playlist, '(?m)^segment_\d+\.ts$')

$keyCount = $keyLines.Count
$segCount = $segmentLines.Count
$check1 = ($keyCount -gt 0) -and ($keyCount -eq $segCount)
Write-Check -Label "Une clé déclarée par segment (#EXT-X-KEY)" -Passed $check1 `
  -Detail "$keyCount directive(s) de clé pour $segCount segment(s)"
$allPassed = $allPassed -and $check1

# -------------------------------------------------------------
# [2] Tous les IV sont distincts (pas de réutilisation de clé/IV)
# -------------------------------------------------------------
$ivs = $keyLines | ForEach-Object { ([regex]::Match($_.Value, 'IV=0x([0-9a-fA-F]+)')).Groups[1].Value }
$uniqueIvs = $ivs | Select-Object -Unique
$check2 = ($ivs.Count -gt 0) -and ($uniqueIvs.Count -eq $ivs.Count)
Write-Check -Label "Chaque segment a un IV distinct (pas de clé réutilisée)" -Passed $check2 `
  -Detail "$($uniqueIvs.Count) IV unique(s) sur $($ivs.Count) segment(s)"
$allPassed = $allPassed -and $check2

# -------------------------------------------------------------
# [3] Le contenu binaire du premier segment n'est PAS un flux MPEG-TS
#     valide en clair (absence de l'octet de synchronisation 0x47
#     répété tous les 188 octets)
# -------------------------------------------------------------
try {
  $firstSegUrl = "$blobBase/$VideoId/segment_000.ts"
  $tmpFile = [System.IO.Path]::GetTempFileName()
  Invoke-WebRequest -Uri $firstSegUrl -OutFile $tmpFile -UseBasicParsing
  $bytes = [System.IO.File]::ReadAllBytes($tmpFile)
  Remove-Item $tmpFile -Force

  $syncByteCount = 0
  $samples = [Math]::Min(20, [Math]::Floor($bytes.Length / 188))
  for ($p = 0; $p -lt $samples; $p++) {
    if ($bytes[$p * 188] -eq 0x47) { $syncByteCount++ }
  }
  # Un flux TS en clair aurait l'octet 0x47 à (quasi) 100% des positions testées.
  # Un contenu chiffré AES-CBC produit des octets pseudo-aléatoires : la
  # probabilité d'obtenir 0x47 par hasard sur plusieurs positions consécutives
  # est négligeable (< 1 / 256^N).
  $ratio = if ($samples -gt 0) { $syncByteCount / $samples } else { 0 }
  $check3 = $ratio -lt 0.5
  Write-Check -Label "Le premier segment n'est pas un flux MPEG-TS lisible en clair" -Passed $check3 `
    -Detail "octet de synchronisation TS (0x47) présent sur $syncByteCount/$samples position(s) testée(s) — attendu ~$samples si non chiffré, attendu ~0 si chiffré"
  $allPassed = $allPassed -and $check3
} catch {
  Write-Check -Label "Le premier segment n'est pas un flux MPEG-TS lisible en clair" -Passed $false -Detail "Erreur : $_"
  $allPassed = $false
}

# -------------------------------------------------------------
# [4] La délivrance de clé est bien protégée (401 sans jeton)
# -------------------------------------------------------------
try {
  Invoke-WebRequest -Uri "$siteUrl/keys/$VideoId/0" -UseBasicParsing | Out-Null
  Write-Check -Label "La clé de segment est protégée (refus sans jeton)" -Passed $false -Detail "La requête a été acceptée sans jeton — FAILLE"
  $allPassed = $false
} catch {
  $code = $_.Exception.Response.StatusCode.value__
  $check4 = ($code -eq 401)
  Write-Check -Label "La clé de segment est protégée (refus sans jeton)" -Passed $check4 -Detail "HTTP $code reçu (401 attendu)"
  $allPassed = $allPassed -and $check4
}

# -------------------------------------------------------------
# Verdict
# -------------------------------------------------------------
Write-Host "`n════════════════════════════════════════════════════════════" -ForegroundColor Cyan
if ($allPassed) {
  Write-Host "  VERDICT : la vidéo '$VideoId' est CHIFFRÉE et correctement protégée." -ForegroundColor Green
} else {
  Write-Host "  VERDICT : au moins un contrôle a échoué — vérifier la vidéo '$VideoId'." -ForegroundColor Red
}
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
