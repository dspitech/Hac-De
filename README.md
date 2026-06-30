# Architecture Zero-Trust -Streaming HLS Chiffré AES-128 sur Azure

## Structure du projet

```
zerotrust-hls/
├── terraform/          # Infrastructure as Code
│   ├── providers.tf
│   ├── variables.tf
│   ├── main.tf
│   └── outputs.tf
├── keyserver/           # Key Server Node.js (JWT + dérivation AES)
│   ├── server.js
│   ├── package.json
│   └── Dockerfile
└── scripts/
    ├── deploy.sh         # Orchestration complète
    ├── package_hls.sh    # Packaging vidéo HLS chiffrée
    └── player.html        # Lecteur de démo (hls.js)
```

## Principes Zero-Trust appliqués

| Principe | Implémentation |
|---|---|
| Pas de confiance implicite | Chaque requête de clé AES exige un JWT valide vérifié à chaque appel |
| Moindre privilège | Le JWT est scopé à un seul `videoId` ; impossible d'accéder aux clés d'autres vidéos |
| Clés éphémères | JWT à durée de vie courte (60s par défaut) |
| Pas de secret persistant | La clé AES est **dérivée** (HMAC-SHA256) à la volée, jamais stockée en base |
| Identité forte des services | Container App utilise une Identité Managée (pas de mot de passe ACR, pas de clé Storage) |
| Stockage protégé | Storage Account sans accès public, Key Vault en RBAC uniquement |
| Surface d'attaque réduite | helmet, CORS strict, rate-limiting, utilisateur non-root dans le conteneur |

## Prérequis (Azure Cloud Shell, Bash)

Cloud Shell contient déjà `az`, `terraform`, `ffmpeg` n'est pas garanti -on l'installe si besoin.

```bash
ffmpeg -version || sudo apt-get update && sudo apt-get install -y ffmpeg xxd
az login   # si pas déjà connecté automatiquement dans Cloud Shell
az account show
```

## Étape 1 -Récupérer les fichiers

Copiez l'arborescence `zerotrust-hls/` fournie dans votre Cloud Shell (upload via le bouton "Upload/Download files" ou `git` si vous la versionnez), puis :

```bash
cd zerotrust-hls
chmod +x scripts/*.sh
```

## Étape 2 -Déployer l'infrastructure et le Key Server

Le script `deploy.sh` fait tout en une fois : `terraform apply`, build de l'image via **ACR Tasks** (donc pas besoin de Docker installé localement dans Cloud Shell), puis ré-application Terraform pour pointer le Container App vers l'image réelle.

```bash
./scripts/deploy.sh
```

À la fin, notez l'URL affichée, par exemple :
```
Key Server disponible à : https://ca-keyserver-ab12c.whitewater-12345678.westeurope.azurecontainerapps.io
```

Vérifiez qu'il répond :
```bash
curl https://<votre-url>/healthz
# {"status":"ok"}
```

## Étape 3 -Packager une vidéo HLS chiffrée

Le `MASTER_KEY` utilisé par le packaging doit être **strictement identique** à celui utilisé par le Key Server. Par défaut, le Key Server retombe sur `JWT_SECRET` si `MASTER_KEY` n'est pas défini séparément. Récupérez-le depuis Key Vault :

```bash
KV_NAME=$(cd terraform && terraform output -raw key_vault_name)
MASTER_KEY=$(az keyvault secret show --vault-name "$KV_NAME" --name jwt-signing-secret --query value -o tsv)
```

Packagez une vidéo locale (mp4) :

```bash
KEY_SERVER_URL="https://<votre-url-key-server>" \
./scripts/package_hls.sh ./ma_video.mp4 demo-video-001 "$MASTER_KEY" ./output
```

Cela génère dans `./output/demo-video-001/` :
- `playlist.m3u8` (référence `https://.../keys/demo-video-001` comme URI de clé)
- `segment_000.ts`, `segment_001.ts`, ... (segments **chiffrés** AES-128)

## Étape 4 -Servir la playlist et tester le pipeline complet

Servez les fichiers statiquement (Cloud Shell ou en local) :

```bash
cd output/demo-video-001
python3 -m http.server 9090
```

Dans un autre terminal/onglet, ouvrez `scripts/player.html` dans votre navigateur (ou servez-le aussi en HTTP), renseignez :
- URL du Key Server → l'URL Azure obtenue à l'étape 2
- video_id → `demo-video-001`
- URL playlist → `http://localhost:9090/playlist.m3u8`

Cliquez sur "Obtenir un JWT et lancer la lecture". Le flux suivant se produit :
1. Le navigateur demande un JWT via `POST /auth/token` (identifiants démo).
2. `hls.js` charge `playlist.m3u8`, voit l'`#EXT-X-KEY` pointant vers le Key Server.
3. `hls.js` appelle `GET /keys/demo-video-001` avec le header `Authorization: Bearer <JWT>`.
4. Le Key Server vérifie le JWT, vérifie que `videoId` correspond, dérive et renvoie la clé AES brute.
5. Le lecteur déchiffre les segments à la volée et joue la vidéo.

## Étape 5 -Démontrer les garanties Zero-Trust

Quelques tests à montrer en démo :

**a) Sans JWT → refus**
```bash
curl -i https://<key-server-url>/keys/demo-video-001
# 401 Token Bearer manquant
```

**b) JWT expiré (>60s) → refus**
```bash
TOKEN=$(curl -s -X POST https://<key-server-url>/auth/token \
  -H "Content-Type: application/json" \
  -d '{"clientId":"demo-client","clientSecret":"demo-secret-changeme","videoId":"demo-video-001"}' \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
sleep 65
curl -i https://<key-server-url>/keys/demo-video-001 -H "Authorization: Bearer $TOKEN"
# 401 Token invalide ou expiré
```

**c) JWT valide mais pour une autre vidéo → refus (moindre privilège)**
```bash
curl -i https://<key-server-url>/keys/AUTRE-VIDEO -H "Authorization: Bearer $TOKEN"
# 403 Token non autorisé pour cette vidéo
```

**d) Segments illisibles sans la clé**
```bash
file output/demo-video-001/segment_000.ts
# Les segments sont chiffrés, leur contenu n'est pas un flux MPEG-TS lisible directement
```

## Sécurisation pour un usage réel (au-delà de cette démo)

- Remplacer `/auth/token` (démo) par une intégration **Azure AD / Entra ID** (OAuth2 / OIDC) avec authentification utilisateur réelle.
- Restreindre `ALLOWED_ORIGINS` au domaine exact du lecteur en production (pas `*`).
- Mettre les segments `.ts` derrière un CDN avec SAS de courte durée plutôt qu'un accès statique simple.
- Stocker `MASTER_KEY` comme secret dédié séparé de `JWT_SECRET` (actuellement, par simplicité de démo, le serveur retombe sur `JWT_SECRET` si `MASTER_KEY` n'est pas fourni).
- Ajouter une politique réseau (Private Endpoints) sur le Storage Account et le Key Vault pour un Zero-Trust réseau complet.
- Activer Microsoft Defender for Containers sur l'environnement Container Apps.

## Nettoyage

```bash
cd terraform
terraform destroy -auto-approve
```
