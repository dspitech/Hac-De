FROM node:20-alpine

WORKDIR /app

COPY package.json .
RUN npm install --omit=dev

COPY server.js .

# Exécution en utilisateur non-root (Zero-Trust: moindre privilège dans le conteneur)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

EXPOSE 8080

CMD ["node", "server.js"]
