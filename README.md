# Zero-Trust HLS - Plateforme de streaming vidéo chiffré sur Azure (sans ACR)

Plateforme complète : **authentification** (Admin / Utilisateur / Invité éphémère), **upload vidéo
avec segmentation HLS + chiffrement AES-128 automatiques**, **CRUD** vidéos/commentaires/utilisateurs,
**délivrance de clé Zero-Trust** via jeton JWT court, et **audit complet** (Table Storage +
Application Insights + Log Analytics). Aucun **Azure Container Registry** requis : le Container App
démarre sur l'image publique `node:20-alpine` et télécharge le code applicatif depuis Blob Storage.
Tout se déploie depuis **Azure Cloud Shell en PowerShell**, ou via le pipeline CI/CD GitHub Actions fourni.

Ce document répond au cahier des charges *« Architecture Zero-Trust - Pipeline CDN Streaming
Chiffré »* (Pôle 2 · Sujet A). La correspondance section par section est donnée en §0.

---

## 0. Correspondance avec le cahier des charges

| Section du cahier des charges | Implémenté ici | Où |
|---|---|---|
| §4.1 Flux de lecture sécurisé (7 étapes) | ✅ intégralement | `keyserver/server.js` (voir en-tête du fichier) |
| §5 Pipeline d'ingestion et packaging HLS chiffré | ✅ `ffmpeg -hls_key_info_file`, clé aléatoire 16 octets, playlist avec `#EXT-X-KEY` | `POST /upload` |
| §6 Chiffrement AES-128 | ✅ AES-128 CBC standard HLS, clé jamais dérivée d'un mot de passe, jamais stockée à côté des segments | `POST /upload` |
| §7 Key Server (F-KS-01 à F-KS-09) | ✅ toutes les fonctionnalités, voir tableau §7 ci-dessous | `server.js` |
| §8 Authentification & tokens temporaires | ✅ jeton de session (login) + jeton clé dérivé, court, scopé à une vidéo | `signSessionToken` / `signKeyToken` |
| §9 CDN & distribution | ⚠️ partiel - voir écarts §0.1 | Blob Storage public en lieu de CDN dédié |
| §10 Stack technique Azure | ✅ sauf Private Endpoint / Redis / Front Door - voir écarts | `terraform/main.tf` |
| §11 Infrastructure as Code | ✅ Terraform complet, `plan`/`apply` reproductibles | `terraform/` |
| §12 Conteneurisation Docker | ⚠️ remplacé par un mécanisme équivalent sans ACR - voir §0.1 | `keyserver/Dockerfile` (test local) |
| §13 Sécurité Zero-Trust par couche | ✅ identité managée partout, RBAC, TLS, secrets hors code | `terraform/main.tf` |
| **§14 Observabilité, logs & audit** | ✅ voir §14 ci-dessous | Application Insights + Table `AuditLog` |
| **§15 CI/CD du pipeline IaC** | ✅ voir §15 ci-dessous | `.github/workflows/iac.yml` |
| §16 Modèle de données | ✅ adapté (Table Storage au lieu d'une base applicative dédiée) | Tables `Users`, `Comments`, `RevokedTokens`, `AuditLog` |
| §17 Exigences non fonctionnelles | ✅ sauf disponibilité 99,9 % (hors périmètre démo étudiant) | - |
| §21 Critères d'évaluation | ✅ tous démontrables (voir §19 scénario de démo) | - |

### 0.1 Écarts assumés par rapport au cahier des charges (et pourquoi)

Le cahier des charges précise explicitement qu'*aucun accès cloud réel n'est fourni ni attendu* et
que la démo peut se faire en local. Ce projet va plus loin : il est **réellement déployé sur Azure**
(compte Azure for Students), ce qui impose quelques simplifications pragmatiques :

| Cahier des charges | Ici | Raison |
|---|---|---|
| Azure Front Door / CDN dédié avec règles de cache différenciées | Lecture publique directe depuis Blob Storage (`container_access_type = "blob"`) | Front Door Premium n'entre pas dans le crédit étudiant ; le comportement recherché (playlist/segments cacheables, clé jamais cacheable) est déjà obtenu via les en-têtes `Cache-Control: no-store` sur `/keys/*` - un Front Door/CDN peut être ajouté devant sans changer le Key Server (extension documentée) |
| Private Endpoint / réseau totalement privé pour Storage et Key Server | Storage et Container App exposés publiquement, mais protégés par identité managée + RBAC + JWT | VNet + Private Endpoint ont un coût et une complexité disproportionnés pour une démo ; le contenu exposé publiquement est **chiffré** (segments) ou **non sensible** (playlist), jamais la clé |
| Azure Cache for Redis pour la liste de révocation | Table Storage (`RevokedTokens`) | Redis Cache a un coût fixe horaire élevé pour un compte étudiant ; Table Storage offre la même sémantique (lookup par clé) pour le volume d'une démo |
| JWT asymétrique RS256 (Core Auth externe signe, Key Server vérifie) | JWT HS256 avec secret partagé interne | Le cahier des charges suppose un Core Auth séparé (Pôle 1, NestJS) ; ici l'authentification et la délivrance de clé sont dans le **même service**, donc un secret partagé est suffisant et plus simple à opérer sans dégrader le modèle de menace (le secret ne quitte jamais le Container App) |
| Azure Container Registry pour les images Docker | Aucun ACR - voir §"Pourquoi ça fonctionne sans ACR" | Contrainte explicite de la demande initiale de ce projet |
| Rotation de clé par segment | Une clé par vidéo (Lot 0 explicitement suffisant selon la FAQ §23 du cahier des charges) | Conforme au périmètre Lot 0 |

---

## 1. Architecture

```
                         UTILISATEUR (navigateur, hls.js)
                                    │ HTTPS
                                    ▼
                  ┌──────────────────────────────────────┐
                  │   AZURE CONTAINER APPS                │
                  │   (Key Server Node.js + ffmpeg)       │
                  │   Identité managée système             │
                  │   Auth · CRUD vidéos/commentaires ·    │
                  │   audit · délivrance de clé            │
                  └───────────────┬────────────────────────┘
                                  │
     ┌──────────────┬─────────────┼─────────────┬──────────────────┐
     ▼              ▼             ▼             ▼                  ▼
┌──────────┐ ┌──────────────┐ ┌──────────┐ ┌──────────────┐ ┌──────────────┐
│ BLOB      │ │ KEY VAULT     │ │ TABLE     │ │ APPLICATION   │ │ LOG           │
│ STORAGE   │ │ clé AES-128   │ │ STORAGE   │ │ INSIGHTS      │ │ ANALYTICS      │
│ - uploads │ │ par vidéo     │ │ Users     │ │ traces,       │ │ logs Storage + │
│ - hls-seg │ │ (RBAC)        │ │ Comments  │ │ dépendances,  │ │ Key Vault +    │
│ - app-code│ │               │ │ Revoked   │ │ événements    │ │ Container Apps │
│           │ │               │ │ AuditLog  │ │ custom        │ │ + App Insights │
└──────────┘ └──────────────┘ └──────────┘ └──────────────┘ └──────────────┘
```

Aucun mot de passe ou clé de stockage n'est utilisé : le Container App s'authentifie auprès de
Storage (Blob + Table), Key Vault via son **identité managée** (rôles RBAC `Storage Blob Data
Contributor`, `Storage Table Data Contributor`, `Key Vault Secrets Officer`).

## 2. Rôles & CRUD

| Rôle | Vidéos | Commentaires | Utilisateurs | Audit | Téléchargement |
|---|---|---|---|---|---|
| **admin** (Professionnel) | CRUD complet (upload, renommer, supprimer) | modération (suppression de tout commentaire) | lecture + suppression de comptes | lecture du journal complet | approuve/refuse les demandes |
| **user** (Utilisateur final) | lecture seule (visionnage) | CRUD sur ses propres commentaires | - | - | peut demander une autorisation |
| **guest** (éphémère) | lecture seule | CRUD sur ses propres commentaires | - | - | peut demander une autorisation ; purgé à la déconnexion |

Le compte `admin` est créé automatiquement au premier démarrage (identifiant/mot de passe générés
par Terraform, affichés à la fin de `deploy.ps1`).

## 2bis. Chiffrement par segment & rotation automatique des clés

Contrairement à un chiffrement HLS classique (une clé unique pour toute la vidéo), cette plateforme
génère **une clé AES-128 par segment** :

- À l'upload, chaque segment `.ts` produit par `ffmpeg` est individuellement chiffré avec sa propre
  clé aléatoire et son propre IV (`encryptSegmentsAndBuildPlaylist` dans `server.js`). La playlist
  contient une directive `#EXT-X-KEY` distincte avant chaque segment, pointant vers
  `/keys/{videoId}/{index}`.
- Chaque clé de segment est stockée séparément dans Key Vault (`hls-key-{videoId}-{index}`).
- **Rotation automatique** (`rotateSegmentKeys`) : tous les segments sont déchiffrés puis rechiffrés
  avec des clés et IV entièrement nouveaux :
  - après l'expiration d'une session de lecture (jeton clé de 120s + 5s de marge) - planifiée à
    chaque `POST /videos/:id/key-token`, c'est-à-dire à chaque lecture ;
  - après l'approbation d'une demande de téléchargement.

  Une fois la rotation effectuée, les anciennes clés délivrées (par exemple interceptées ou mises en
  cache par un client malveillant) ne permettent plus de déchiffrer les segments stockés - la
  fenêtre d'exploitation d'une clé volée est donc limitée à la durée de la session qui l'a obtenue.

> **Limite connue documentée** : la planification de rotation utilise `setTimeout` en mémoire dans
> le processus Node.js. Sur un redémarrage du Container App ou avec plusieurs réplicas actifs
> simultanément, une rotation planifiée peut être perdue (la vidéo reste chiffrée et lisible avec
> les clés courantes, seule la rotation planifiée n'a pas lieu). Extension possible pour la
> production : remplacer par une file de tâches durable (Azure Storage Queue + Container Apps Jobs).

## 2ter. Téléchargement protégé par autorisation admin

1. Un utilisateur (ou invité) clique sur **⬇ Télécharger** dans le lecteur. Une pop-up centrée
   s'affiche : *« Vous n'avez pas les droits. Cette vidéo est protégée. Veuillez demander une
   autorisation. »* avec un bouton pour envoyer la demande.
2. La demande apparaît dans **Administration → Demandes de téléchargement**, avec boutons
   Approuver/Refuser.
3. À l'approbation :
   - le fichier source original est chiffré en entier avec une **clé d'export dédiée**, distincte
     des clés de streaming ;
   - le fichier chiffré (`.enc`) est déposé dans un container privé `downloads` ;
   - la clé d'export est stockée dans Key Vault avec une **expiration native** (`expiresOn`,
     `DOWNLOAD_KEY_TTL_HOURS`, 24h par défaut) ;
   - les clés de streaming de la vidéo sont aussi rotées par précaution.
4. L'utilisateur voit la pop-up passer à *« Autorisation accordée »*, télécharge le fichier `.enc`,
   puis ouvre **`offline-player.html`** pour le lire : cette page demande la clé de déchiffrement au
   serveur (`GET /videos/:id/download-key`), déchiffre le fichier **entièrement dans le navigateur**
   (Web Crypto API, `AES-CBC`), et lit la vidéo en clair localement - le fichier en clair n'est
   jamais renvoyé au serveur.
5. Passé le délai d'expiration, `download-key` répond `410 Gone` (la clé n'existe plus ou n'est plus
   accessible dans Key Vault, en plus d'un contrôle applicatif sur `downloadKeyExpiresAt`) : le
   fichier `.enc` déjà téléchargé devient définitivement illisible, même hors ligne, tant qu'aucune
   nouvelle autorisation n'est accordée.

## 3. Flux de lecture protégée (conforme §4.1 du cahier des charges)

1. L'utilisateur authentifié (jeton de session obtenu au login) demande la playlist `.m3u8`
2. La playlist est servie publiquement - elle contient **une directive `#EXT-X-KEY` par segment**,
   chacune référençant l'URI de sa propre clé, jamais la clé elle-même
3. `hls.js` demande d'abord un **jeton clé** court (`POST /videos/:id/key-token`, réservé aux
   sessions authentifiées), puis appelle `GET /keys/:id/:segIndex` pour chaque segment avec ce jeton
4. Le Key Server vérifie signature, type de jeton, `videoId`, expiration, révocation
5. Si autorisé : lecture de la clé AES-128 du segment dans Key Vault, réponse binaire brute,
   `Cache-Control: no-store`
6. `hls.js` déchiffre chaque segment `.ts` à la volée (clé différente à chaque changement de segment)
7. Chaque délivrance de clé (et chaque action sensible) est journalisée ; une fois la session de
   lecture terminée, toutes les clés de la vidéo sont automatiquement rotées (§2bis)

## 3bis. Vérifier qu'une vidéo est bien chiffrée

```powershell
./scripts/verify-encryption.ps1                  # liste les vidéos et laisse choisir
./scripts/verify-encryption.ps1 -VideoId <uuid>   # vérifie directement une vidéo précise
```

Le script effectue 4 contrôles techniques indépendants, sans jamais utiliser de clé de compte de
stockage :
1. La playlist contient bien une directive `#EXT-X-KEY` par segment
2. Tous les IV (vecteurs d'initialisation) sont distincts (aucune clé/IV réutilisé)
3. Le premier segment `.ts`, lu directement depuis le Storage, **n'a pas** la structure d'un flux
   MPEG-TS valide en clair (absence de l'octet de synchronisation `0x47` attendu tous les 188 octets
   dans un flux non chiffré)
4. La route `/keys/:videoId/0` refuse l'accès sans jeton (`HTTP 401`)

## 4. Structure du projet

```
Hac-De/
├── keyserver/
│   ├── server.js          # auth, CRUD, ffmpeg, clés par segment, rotation, téléchargement, audit
│   ├── package.json
│   ├── Dockerfile          # test local uniquement, non utilisé sur Azure
│   └── public/              # SPA (HTML/CSS/JS, hls.js)
│       ├── index.html        # hero, marketing, login, bibliothèque, admin, modal téléchargement
│       ├── status.html       # page de statut publique (§4.5 cahier des charges Pôle 1)
│       ├── offline-player.html # lecteur hors-ligne, déchiffrement client-side (Web Crypto)
│       ├── app.js
│       └── style.css
├── terraform/
│   ├── main.tf              # toutes les ressources Azure (5 tables, 3 containers, Key Vault, etc.)
│   ├── variables.tf
│   ├── outputs.tf
│   └── files/                # généré par deploy.ps1 (app-package.zip)
├── scripts/
│   ├── deploy.ps1
│   ├── demo.ps1
│   ├── verify-encryption.ps1  # preuve technique qu'une vidéo est chiffrée
│   └── cleanup.ps1
├── .github/workflows/
│   └── iac.yml               # pipeline CI/CD (lint, plan, apply)
└── README.md
```

## 5. Déploiement (Azure Cloud Shell - PowerShell)

1. Ouvrez **Azure Cloud Shell** et choisissez **PowerShell**.
2. Importez ce projet :
   ```powershell
   Expand-Archive Hac-De.zip -DestinationPath .
   cd Hac-De
   ```
3. Lancez le déploiement :
   ```powershell
   ./scripts/deploy.ps1
   ```
   Ce script package `keyserver/`, exécute `terraform init/validate/apply` (Resource Group, Storage,
   4 Tables, Key Vault, Log Analytics, Application Insights, Container Apps Environment, Container
   App, rôles RBAC, diagnostic settings), attend le démarrage du conteneur, puis affiche l'URL du
   site **et les identifiants du compte administrateur généré automatiquement**.
4. Ouvrez l'URL, connectez-vous avec le compte admin affiché (ou créez un compte utilisateur, ou
   continuez en invité), téléversez une vidéo (admin uniquement), commentez, consultez le journal
   d'audit dans l'onglet Administration.
5. Vérification en ligne de commande : `./scripts/demo.ps1`
6. Nettoyage en fin de démo : `./scripts/cleanup.ps1`

## 6. Pourquoi ça fonctionne sans ACR

Le Container App surcharge la commande de démarrage de l'image publique `node:20-alpine` :

```sh
apk add --no-cache ffmpeg curl unzip
curl -fsSL "$APP_PACKAGE_URL" -o /tmp/app.zip
unzip -q /tmp/app.zip -d /app
cd /app && npm install --omit=dev
node server.js
```

`APP_PACKAGE_URL` pointe vers le `.zip` du code, uploadé par Terraform
(`azurerm_storage_blob.app_package`) dans un container Blob en lecture publique - le code n'a aucun
secret en dur (tous les secrets viennent de variables d'environnement / Key Vault / secrets Container App).

## 7. Fonctionnalités du Key Server (F-KS-01 à F-KS-09)

| ID | Fonctionnalité | Implémentation |
|---|---|---|
| F-KS-01 | `GET /keys/:videoId/:segIndex` | binaire 16 octets, `application/octet-stream`, une clé distincte par segment |
| F-KS-02 | Vérification signature JWT | `jwt.verify` avec `JWT_SECRET`, algorithme HS256 |
| F-KS-03 | Vérification du scope | `payload.videoId === req.params.videoId` |
| F-KS-04 | Vérification d'expiration | `expiresIn` court (120s par défaut) sur le jeton clé |
| F-KS-05 | Révocation | Table `RevokedTokens`, vérifiée à chaque requête de session |
| F-KS-06 | Rate limiting | `express-rate-limit` global + un limiteur dédié par IP+vidéo sur `/keys/:id` |
| F-KS-07 | Journalisation systématique | fonction `audit()` : stdout + Table `AuditLog` + Application Insights |
| F-KS-08 | Pas de cache long terme de la clé | la clé est relue dans Key Vault à chaque requête, jamais mise en cache applicatif |
| F-KS-09 | Health check | `GET /healthz` |

## 8. Modèle de données (Table Storage, équivalent §16)

```
Users              PartitionKey="user"     RowKey=username        {passwordHash, role, ephemeral, createdAt}
Comments           PartitionKey=videoId    RowKey=commentId(uuid) {username, text, createdAt}
RevokedTokens      PartitionKey="revoked"  RowKey=jti              {revokedAt, username}
AuditLog           PartitionKey=type       RowKey=uuid              {username, videoId, ip, result, detail, ts}
DownloadRequests   PartitionKey=videoId    RowKey=requestId(uuid)   {username, status, requestedAt, decidedAt, decidedBy, downloadKeyExpiresAt, exportBlobName}
```

Les métadonnées de vidéo (titre, propriétaire, date, nombre de segments) sont stockées en
`meta.json` à côté des segments dans `hls-segments/{videoId}/meta.json`. Les clés, elles, restent
exclusivement dans Key Vault :
- `hls-key-{videoId}-{segmentIndex}` - une clé de streaming par segment, rotée automatiquement
- `dl-key-{requestId}` - une clé d'export par téléchargement approuvé, avec expiration native Key Vault

## 14. Observabilité, logs & audit

| ID | Fonctionnalité | Implémentation |
|---|---|---|
| F-OBS-01 | Logs structurés du Key Server | `console.log(JSON.stringify(...))` sur chaque requête et chaque événement d'audit - capté par Container Apps → Log Analytics (table `ContainerAppConsoleLogs_CL`) |
| F-OBS-02 | Dashboard | Requêtable via **Application Insights** (`requests`, `customEvents`) ou Log Analytics (KQL) : nombre de délivrances de clé/minute, taux 401/403, latence |
| F-OBS-03 | Alertes | Base prête via Application Insights (alertes sur `customEvents` où `result != "granted"`) - à activer dans le portail Azure selon les seuils souhaités |
| F-OBS-04 | Consultation applicative | Page **Administration → Journal d'audit** du site : liste les 100-500 derniers événements (login, logout, upload, delete, commentaires, délivrances de clé) directement depuis la Table `AuditLog` |
| F-OBS-05 | Traces distribuées | `applicationinsights` SDK Node, auto-collecte requêtes/dépendances/exceptions, connecté au même workspace Log Analytics que Storage et Key Vault |
| F-OBS-06 | Rétention | Log Analytics configuré à 30 jours (`retention_in_days`) ; Table Storage n'a pas de TTL automatique - à ajouter en Lot 1 (purge périodique via Azure Function planifiée) si besoin de conformité RGPD stricte |

Toute délivrance de clé (`granted`/`denied`) et toute action sensible (login, logout, upload,
suppression, CRUD commentaires) passe par la fonction unique `audit()` dans `server.js`, qui écrit
simultanément dans les trois couches ci-dessus - c'est la même source de vérité qui alimente le
dashboard Admin, Application Insights et Log Analytics.

## 15. CI/CD du pipeline IaC

Fichier : `.github/workflows/iac.yml`. Trois jobs :

| Job | Déclencheur | Ce qu'il fait |
|---|---|---|
| `lint-and-validate` | Toute PR touchant `terraform/` ou `keyserver/` | `terraform fmt -check`, packaging factice du code, `terraform init -backend=false` + `terraform validate` (**sans credentials Azure**, conforme §11.5/§15 du cahier des charges), scan `tfsec`, `npm audit` |
| `terraform-plan` | Pull request | Authentification OIDC (`azure/login`, sans secret statique), `terraform plan`, plan posté en commentaire de la PR |
| `terraform-apply` | Push sur `main` | Apply automatique, protégé par l'environnement GitHub **`production`** (approbation manuelle à activer dans *Settings → Environments*) |

### Configuration requise pour activer le pipeline complet (OIDC, sans secret statique)

```bash
# 1. Créer une App Registration + fédération d'identité (à faire une fois)
az ad app create --display-name "github-iac-ztstream"
az ad sp create --id <appId>
az ad app federated-credential create --id <appId> --parameters '{
  "name": "github-main",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:<org>/<repo>:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]
}'

# 2. Donner les droits Contributor sur le Resource Group cible
az role assignment create --assignee <appId> --role Contributor \
  --scope /subscriptions/<sub-id>/resourceGroups/rg-ztstream-demo

# 3. Ajouter en secrets GitHub (Settings → Secrets and variables → Actions) :
#    AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID
```

> Sur certains tenants Azure for Students, la création d'App Registration peut être restreinte aux
> administrateurs du tenant. Dans ce cas, le job `lint-and-validate` (fmt/validate/tfsec, sans
> credentials) reste pleinement fonctionnel et couvre déjà l'essentiel du critère §15 ; `plan`/`apply`
> automatisés restent une extension optionnelle documentée.

## 16. Sécurité Zero-Trust - synthèse par couche (§13)

| Couche | Mesure appliquée ici |
|---|---|
| Identité | Managed Identity pour tout accès Storage/Key Vault ; aucun secret statique Azure dans le code ou les variables d'env |
| Authentification | JWT à courte durée pour la clé (120s), session à durée modérée (2h, 30 min pour les invités), vérifié à chaque requête |
| Autorisation | Scope strict par jeton (`videoId`, `role`), vérifié côté serveur indépendamment du frontend |
| Chiffrement en transit | TLS obligatoire (`min_tls_version = TLS1_2`, ingress HTTPS Container Apps) |
| Chiffrement applicatif | AES-128 sur les segments, indépendant du TLS |
| Secrets | JWT secret et mot de passe admin générés aléatoirement par Terraform, injectés en tant que *secrets* Container App (jamais en variable d'environnement en clair) ; clé AES exclusivement dans Key Vault |
| Surface d'exposition | Seul le Container App est exposé publiquement ; le stockage brut (`uploads`) reste privé |
| Révocation | Table `RevokedTokens` consultée à chaque requête de session ; logout = révocation immédiate |
| Journalisation | 100 % des délivrances de clé et actions sensibles auditées (voir §14) |
| Moindre privilège | Rôles RBAC dédiés et minimaux : `Storage Blob Data Contributor`, `Storage Table Data Contributor`, `Key Vault Secrets Officer` - scope limité au compte de stockage / coffre concerné |

## 17. Coûts (compte Azure Students)

Toutes les ressources entrent dans les paliers gratuits/peu coûteux : Container Apps (180 000
vCPU-s gratuits/mois), Blob + Table Storage (quelques Mo/Go), Key Vault (facturé à l'opération,
négligeable), Log Analytics (30 jours de rétention, faible volume), Application Insights (basé sur
le même workspace, pas de ressource facturée séparément au-delà de l'ingestion). Exécutez
`cleanup.ps1` après chaque démo.

## 18. Dépannage

- **HTTP 403 sur `/upload` ou `/videos` juste après le déploiement** : propagation RBAC (1-2 min). Réessayez.
- **Le site ne répond pas tout de suite** : premier démarrage = `apk add ffmpeg` + `npm install` (~1-2 min). Logs :
  ```powershell
  az containerapp logs show --name <container_app_name> --resource-group rg-ztstream-demo --follow
  ```
- **Mot de passe admin perdu** : `terraform output -raw admin_password` depuis `terraform/`.
- **Modifier le code et redéployer** : relancez `./scripts/deploy.ps1` - Terraform détecte le
  changement du `.zip` (`filemd5`) et déploie une nouvelle révision.
- **Un compte invité ne peut pas se reconnecter** : c'est voulu - les comptes invités sont éphémères
  et supprimés à la déconnexion, avec purge de leurs propres vidéos de test.
- **Vérifier qu'une vidéo est bien chiffrée** : `./scripts/verify-encryption.ps1 -VideoId <uuid>`
  (voir §3bis) - utile après un upload pour prouver le chiffrement sans faire confiance à l'interface.
- **Un fichier téléchargé ne se lit plus** : c'est voulu si le délai `DOWNLOAD_KEY_TTL_HOURS` (24h par
  défaut) est dépassé - refaites une demande de téléchargement depuis la plateforme.
