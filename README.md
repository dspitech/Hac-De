# Zero-Trust HLS — Streaming vidéo chiffré sur Azure (sans ACR)

Démo pédagogique : une page web permet d'**uploader une vidéo**, qui est
automatiquement **découpée en segments HLS** et **chiffrée en AES‑128**.
Chaque segment chiffré est stocké publiquement (inutile de le protéger,
il est illisible sans clé), et la **clé n'est délivrée qu'après vérification
d'un jeton JWT**, elle-même stockée dans **Azure Key Vault** et jamais
codée en dur nulle part.

Aucun **Azure Container Registry** n'est utilisé : le Container App démarre
sur l'image publique `node:20-alpine`, télécharge le code applicatif (un
simple `.zip` déposé dans Blob Storage par Terraform) et installe `ffmpeg`
au démarrage. Tout se déploie depuis **Azure Cloud Shell en PowerShell**.

## Architecture

```
                         UTILISATEUR (navigateur, hls.js)
                                    │ HTTPS
                                    ▼
                  ┌──────────────────────────────────┐
                  │   AZURE CONTAINER APPS            │
                  │   (Key Server Node.js + ffmpeg)   │
                  │   Identité managée système        │
                  └───────────────┬────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        ▼                         ▼                         ▼
┌────────────────┐      ┌──────────────────┐      ┌──────────────────────┐
│ BLOB STORAGE    │      │ KEY VAULT         │      │ LOG ANALYTICS         │
│ - uploads (priv)│      │ clé AES-128       │      │ logs Storage +        │
│ - hls-segments  │      │ par vidéo (RBAC)  │      │ Key Vault + Container │
│   (lecture pub) │      │                   │      │ Apps                  │
│ - app-code      │      │                   │      │                       │
└────────────────┘      └──────────────────┘      └──────────────────────┘
```

Aucun mot de passe ou clé de stockage n'est utilisé : le Container App
s'authentifie auprès de Storage et Key Vault uniquement via son
**identité managée** (rôles RBAC `Storage Blob Data Contributor` et
`Key Vault Secrets Officer`, assignés par Terraform).

## Structure du projet

```
Hac-De/
├── keyserver/
│   ├── server.js          # upload, ffmpeg, JWT, clés Key Vault
│   ├── package.json
│   ├── Dockerfile          # test local uniquement, non utilisé sur Azure
│   └── public/              # site web (HTML/CSS/JS, hls.js)
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── files/                # généré par deploy.ps1 (app-package.zip)
├── scripts/
│   ├── deploy.ps1
│   ├── demo.ps1
│   └── cleanup.ps1
└── README.md
```

## Déploiement (Azure Cloud Shell — PowerShell)

1. Ouvrez **Azure Cloud Shell** et choisissez **PowerShell** (pas Bash).
2. Importez ce projet (uploadez le zip puis décompressez, ou `git clone` si
   vous l'avez poussé sur un repo) :
   ```powershell
   Expand-Archive Hac-De.zip -DestinationPath .
   cd Hac-De
   ```
3. Lancez le déploiement :
   ```powershell
   ./scripts/deploy.ps1
   ```
   Ce script :
   - package `keyserver/` en `.zip` (sans `node_modules`, sans `Dockerfile`)
   - exécute `terraform init / plan / apply` (Resource Group, Storage,
     Key Vault, Log Analytics, Container Apps Environment, Container App,
     rôles RBAC, diagnostic settings)
   - attend que le Container App démarre (premier démarrage : ~1-2 min, le
     temps d'`apk add ffmpeg` + `npm install`)
   - affiche l'URL du site

4. Ouvrez l'URL affichée : **téléversez une vidéo**, elle est segmentée et
   chiffrée automatiquement, puis lisez-la — la clé est récupérée via JWT
   en coulisses.

5. Pour vérifier que tout fonctionne en ligne de commande :
   ```powershell
   ./scripts/demo.ps1
   ```

6. Pour tout supprimer en fin de démo (important sur un compte Azure
   Students à crédit limité) :
   ```powershell
   ./scripts/cleanup.ps1
   ```

## Pourquoi ça fonctionne sans ACR

Un Container App a normalement besoin d'une image construite et poussée
quelque part (souvent ACR). Ici, on utilise l'image **publique**
`node:20-alpine` telle quelle, et on surcharge sa commande de démarrage :

```sh
apk add --no-cache ffmpeg curl unzip
curl -fsSL "$APP_PACKAGE_URL" -o /tmp/app.zip
unzip -q /tmp/app.zip -d /app
cd /app && npm install --omit=dev
node server.js
```

`APP_PACKAGE_URL` pointe vers le `.zip` du code, uploadé par Terraform
(`azurerm_storage_blob.app_package`) dans un container Blob en lecture
publique (`app-code`) — le code n'a aucun secret en dur, donc ce n'est
pas un risque (tous les secrets viennent de variables d'environnement /
Key Vault).

## Ce qui rend l'infra "Zero-Trust"

- **Aucune clé de compte de stockage** n'est utilisée par l'application
  (identité managée uniquement).
- **Aucun secret** dans le code ou dans l'image : `JWT_SECRET` est généré
  aléatoirement par Terraform et injecté en tant que *secret* Container App.
- La **clé AES-128 de chaque vidéo** est générée à l'upload, stockée
  uniquement dans Key Vault, et n'est lue qu'à la demande, après
  vérification d'un JWT à durée de vie courte (120s par défaut) lié au
  `videoId`.
- Les segments `.ts` et la playlist `.m3u8` sont publics, mais **inutiles
  sans la clé** : c'est le modèle utilisé par les vraies plateformes de
  streaming (HLS + AES-128 + key delivery server protégé).
- **Log Analytics** reçoit les journaux d'accès du Storage, les
  `AuditEvent` du Key Vault et les logs système du Container App : toute
  tentative d'accès est traçable.

## Coûts (compte Azure Students)

Toutes les ressources utilisées entrent dans les paliers gratuits/peu
coûteux : Container Apps (180 000 vCPU‑s gratuits/mois), Blob Storage
(quelques Mo/Go pour une démo), Key Vault (opérations facturées au
nombre, négligeable), Log Analytics (30 jours de rétention, faible
volume). Pensez à exécuter `cleanup.ps1` après votre démo.

## Dépannage

- **HTTP 403 sur `/upload` juste après le déploiement** : la propagation
  des rôles RBAC (Storage / Key Vault) peut prendre 1-2 minutes après
  `terraform apply`. Réessayez.
- **Le site ne répond pas tout de suite** : le premier démarrage du
  conteneur installe `ffmpeg` via `apk` — comptez 1 à 2 minutes.
  Suivez les logs avec :
  ```powershell
  az containerapp logs show --name <container_app_name> --resource-group rg-ztstream-demo --follow
  ```
- **Modifier le code et redéployer** : relancez simplement
  `./scripts/deploy.ps1` — Terraform détecte le changement du `.zip`
  (`filemd5`) et redéploie une nouvelle révision du Container App.
