#!/usr/bin/env bash
#
# Packageur HLS chiffré AES-128, cohérent avec le Key Server Zero-Trust.
#
# La clé AES utilisée pour chiffrer les segments est dérivée de la MÊME façon
# que côté Key Server : HMAC-SHA256(MASTER_KEY, videoId) tronqué à 16 octets.
# Ainsi, aucune clé n'est stockée ni transmise en clair : seul MASTER_KEY est
# un secret partagé (déployé via Key Vault côté Azure).
#
# Usage:
#   ./package_hls.sh <video_input.mp4> <video_id> <master_key_hex_or_string> [output_dir]
#
# Exemple:
#   ./package_hls.sh demo.mp4 demo-video-001 "$MASTER_KEY" ./output

set -euo pipefail

INPUT_VIDEO="${1:?Usage: $0 <input.mp4> <video_id> <master_key> [output_dir]}"
VIDEO_ID="${2:?video_id requis}"
MASTER_KEY="${3:?master_key requis (doit correspondre à MASTER_KEY du Key Server)}"
OUTPUT_DIR="${4:-./output/$VIDEO_ID}"
KEY_SERVER_URL="${KEY_SERVER_URL:-http://localhost:8080}"

command -v ffmpeg >/dev/null 2>&1 || { echo "ffmpeg requis. Installez-le : sudo apt-get install -y ffmpeg"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "openssl requis."; exit 1; }
command -v xxd >/dev/null 2>&1 || { echo "xxd requis (paquet vim-common / xxd)."; exit 1; }

mkdir -p "$OUTPUT_DIR"

echo "==> Dérivation de la clé AES-128 pour videoId=$VIDEO_ID (HMAC-SHA256 tronqué)"
# Reproduit exactement crypto.createHmac('sha256', MASTER_KEY).update(videoId).digest().subarray(0,16)
AES_KEY_HEX=$(printf "%s" "$VIDEO_ID" | openssl dgst -sha256 -hmac "$MASTER_KEY" -binary | xxd -p -c 256 | cut -c1-32)
echo "$AES_KEY_HEX" | xxd -r -p > "$OUTPUT_DIR/enc.key"

# IV fixe et déterministe par vidéo (dérivé aussi, pour la démo ; en prod, un IV
# aléatoire par segment géré via keyinfo serait préférable mais complique la démo)
AES_IV_HEX=$(printf "%s" "${VIDEO_ID}-iv" | openssl dgst -sha256 -hmac "$MASTER_KEY" -binary | xxd -p -c 256 | cut -c1-32)

# Fichier keyinfo pour ffmpeg :
# ligne 1 = URI publique de la clé (pointera vers le Key Server, PAS un fichier local)
# ligne 2 = chemin local vers la clé réelle (utilisé seulement pour le chiffrement par ffmpeg)
# ligne 3 = IV en hexadécimal
KEYINFO_FILE="$OUTPUT_DIR/keyinfo.txt"
cat > "$KEYINFO_FILE" <<EOF
${KEY_SERVER_URL}/keys/${VIDEO_ID}
${OUTPUT_DIR}/enc.key
${AES_IV_HEX}
EOF

echo "==> Packaging HLS chiffré AES-128 avec ffmpeg"
ffmpeg -y -i "$INPUT_VIDEO" \
  -c:v h264 -c:a aac \
  -hls_time 6 \
  -hls_playlist_type vod \
  -hls_key_info_file "$KEYINFO_FILE" \
  -hls_segment_filename "$OUTPUT_DIR/segment_%03d.ts" \
  "$OUTPUT_DIR/playlist.m3u8"

# Par sécurité : on supprime la clé locale en clair une fois le packaging fait.
# Elle n'est plus nécessaire (le Key Server la re-dérive à la volée).
rm -f "$OUTPUT_DIR/enc.key"

echo "==> Terminé. Fichiers générés dans $OUTPUT_DIR :"
ls -la "$OUTPUT_DIR"
echo ""
echo "Le fichier playlist.m3u8 référence la clé via : ${KEY_SERVER_URL}/keys/${VIDEO_ID}"
echo "Pour lire la vidéo, le lecteur doit d'abord obtenir un JWT via POST ${KEY_SERVER_URL}/auth/token"
echo "puis présenter ce token en header Authorization: Bearer <token> lors de l'appel à /keys/${VIDEO_ID}."
