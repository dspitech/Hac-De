# Ce Dockerfile sert UNIQUEMENT pour tester en local (docker run).
# Le déploiement Azure n'utilise PAS cette image (pas d'ACR) : voir
# terraform/main.tf, le Container App télécharge le code et installe
# ffmpeg au démarrage à partir de l'image publique node:20-alpine.

FROM node:20-alpine

RUN apk add --no-cache ffmpeg

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY server.js .
COPY public ./public

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:8080/healthz || exit 1

CMD ["node", "server.js"]
