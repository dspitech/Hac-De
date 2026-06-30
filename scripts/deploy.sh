#!/usr/bin/env bash
# Orchestration complète : Terraform -> build/push image Key Server -> mise à jour Container App
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== 1/4 : Terraform init/apply (infrastructure de base) ==="
cd terraform
terraform init
terraform apply -auto-approve

ACR_NAME=$(terraform output -raw acr_name)
ACR_LOGIN_SERVER=$(terraform output -raw acr_login_server)
RESOURCE_GROUP=$(terraform output -raw resource_group)
cd ..

echo "=== 2/4 : Build & push de l'image Key Server via ACR Tasks (pas de Docker local requis) ==="
az acr build \
  --registry "$ACR_NAME" \
  --image keyserver:latest \
  ./keyserver

echo "=== 3/4 : Re-apply Terraform en pointant vers l'image buildée ==="
cd terraform
terraform apply -auto-approve -var "key_server_image=${ACR_LOGIN_SERVER}/keyserver:latest"
KEY_SERVER_URL=$(terraform output -raw key_server_fqdn)
cd ..

echo "=== 4/4 : Déploiement terminé ==="
echo "Key Server disponible à : $KEY_SERVER_URL"
echo "Resource Group         : $RESOURCE_GROUP"
echo ""
echo "Pensez à définir le secret MASTER_KEY sur le Container App (séparé du JWT_SECRET)"
echo "via : az containerapp secret set ... ou en ajoutant une variable Terraform dédiée."
