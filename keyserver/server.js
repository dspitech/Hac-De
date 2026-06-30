/**
 * Key Server Zero-Trust pour streaming HLS chiffré AES-128.
 *
 * Principes Zero-Trust appliqués :
 *  - Aucune confiance implicite : chaque requête de clé doit présenter un JWT valide.
 *  - Moindre privilège : le JWT contient un "videoId" et le serveur ne délivre QUE
 *    la clé correspondant à CE videoId (pas d'accès large à toutes les vidéos).
 *  - Clés éphémères : les JWT ont une durée de vie très courte (par défaut 60s),
 *    limitant la fenêtre d'exploitation en cas de fuite du token.
 *  - Pas de secret stocké côté serveur par vidéo : la clé AES est dérivée à la volée
 *    via HMAC-SHA256(MASTER_KEY, videoId), donc rien n'est persistant à compromettre.
 *  - Aucun champ "Authorization" n'est journalisé (cf. middleware de logs).
 *  - Surface d'attaque réduite : helmet (en-têtes sécurité), CORS strict, rate-limit.
 */

const express = require("express");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
app.use(express.json());
app.use(helmet());

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;
const MASTER_KEY = process.env.MASTER_KEY || JWT_SECRET; // dérivation des clés AES par vidéo
const TOKEN_TTL_SECONDS = parseInt(process.env.TOKEN_TTL_SECONDS || "60", 10);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*").split(",");

if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET manquant. Le Key Server ne peut pas démarrer sans secret.");
  process.exit(1);
}

app.use(
  cors({
    origin: ALLOWED_ORIGINS.includes("*") ? true : ALLOWED_ORIGINS,
    methods: ["GET", "POST"],
  })
);

// Rate limiting global : protège contre le brute-force de sessionId / scan de vidéos
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Logs sans jamais exposer le header Authorization
app.use((req, res, next) => {
  const safeHeaders = { ...req.headers };
  delete safeHeaders.authorization;
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

/**
 * Dérive une clé AES-128 (16 octets) déterministe pour un videoId donné,
 * à partir du secret maître. Aucune clé n'est stockée en base : c'est une
 * fonction pure, donc le packaging HLS (script ffmpeg) peut dériver la même
 * clé indépendamment via le même MASTER_KEY pour chiffrer les segments.
 */
function deriveAesKey(videoId) {
  return crypto
    .createHmac("sha256", MASTER_KEY)
    .update(videoId)
    .digest()
    .subarray(0, 16); // AES-128 = 16 octets
}

/**
 * Endpoint de démonstration uniquement : émet un JWT de courte durée.
 * Dans une vraie architecture Zero-Trust, cet endpoint serait remplacé par
 * un véritable Identity Provider (Azure AD / Entra ID) avec authentification
 * forte de l'utilisateur. Ici, on simule l'émission après vérification d'un
 * identifiant client statique, à des fins de démo locale uniquement.
 */
const DEMO_CLIENT_ID = process.env.DEMO_CLIENT_ID || "demo-client";
const DEMO_CLIENT_SECRET = process.env.DEMO_CLIENT_SECRET || "demo-secret-changeme";

app.post("/auth/token", (req, res) => {
  const { clientId, clientSecret, videoId } = req.body || {};

  if (!videoId || typeof videoId !== "string") {
    return res.status(400).json({ error: "videoId requis" });
  }

  if (clientId !== DEMO_CLIENT_ID || clientSecret !== DEMO_CLIENT_SECRET) {
    return res.status(401).json({ error: "Identifiants invalides" });
  }

  const token = jwt.sign(
    { sub: clientId, videoId, scope: "hls:key:read" },
    JWT_SECRET,
    { expiresIn: TOKEN_TTL_SECONDS, algorithm: "HS256" }
  );

  res.json({ access_token: token, token_type: "Bearer", expires_in: TOKEN_TTL_SECONDS });
});

/**
 * Middleware Zero-Trust : vérifie le JWT à CHAQUE requête (pas de session
 * persistante, pas de cookie). Vérifie aussi que le videoId du token
 * correspond exactement au videoId demandé (principe du moindre privilège).
 */
function verifyJwtForVideo(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) {
    return res.status(401).json({ error: "Token Bearer manquant" });
  }

  try {
    const payload = jwt.verify(match[1], JWT_SECRET, { algorithms: ["HS256"] });
    if (payload.videoId !== req.params.videoId) {
      return res.status(403).json({ error: "Token non autorisé pour cette vidéo" });
    }
    req.tokenPayload = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token invalide ou expiré" });
  }
}

/**
 * Endpoint consommé directement par le lecteur HLS comme KEYFORMATURI
 * (champ URI de la ligne #EXT-X-KEY du fichier .m3u8). Retourne la clé
 * AES-128 brute en binaire, comme l'exige la spec HLS.
 */
app.get("/keys/:videoId", verifyJwtForVideo, (req, res) => {
  const key = deriveAesKey(req.params.videoId);
  res.set("Content-Type", "application/octet-stream");
  res.send(key);
});

app.get("/healthz", (req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`Key Server Zero-Trust démarré sur le port ${PORT}`);
});
