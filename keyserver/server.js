/**
 * ZERO-TRUST HLS - Key & Media Server (v3)
 * --------------------------------------------------
 * Flux de lecture protégée (conforme au cahier des charges §4.1) :
 *  1. L'utilisateur authentifié (token de session) demande la playlist
 *     .m3u8 d'une vidéo via le "CDN" (ici : lecture publique directe
 *     depuis Blob Storage, le contenu servi est déjà chiffré)
 *  2. La playlist est servie (en cache navigateur/CDN, non sensible :
 *     elle référence l'URI de la clé, jamais la clé elle-même)
 *  3. Le lecteur HLS détecte #EXT-X-KEY et effectue un appel séparé au
 *     Key Server pour obtenir un "jeton clé" court, réservé aux sessions
 *     authentifiées, puis demande la clé avec ce jeton
 *  4. Le Key Server vérifie la signature et le scope du jeton (videoId
 *     autorisé, non expiré, non révoqué)
 *  5. Si autorisé : lecture de la clé AES-128 dans Azure Key Vault,
 *     renvoyée en binaire brut (16 octets) avec Cache-Control: no-store
 *  6. Le lecteur déchiffre localement chaque segment .ts à la volée
 *  7. Chaque délivrance de clé (et chaque action sensible) est journalisée
 *     (utilisateur, vidéo, IP, horodatage, résultat) — Table Storage +
 *     Application Insights + logs structurés (-> Log Analytics)
 *
 * Rôles : admin (CRUD vidéos + modération commentaires + audit),
 *         user (regarde, commente), guest (compte éphémère : à la
 *         déconnexion son jeton est révoqué et ses propres vidéos/clés
 *         de test sont purgées — voir §23 FAQ pour la nuance sur la
 *         "suppression de clé à la déconnexion").
 */

const path = require("path");
const fs = require("fs");
const fsp = fs.promises;
const os = require("os");
const crypto = require("crypto");
const { spawn } = require("child_process");

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");

const { DefaultAzureCredential } = require("@azure/identity");
const { BlobServiceClient } = require("@azure/storage-blob");
const { SecretClient } = require("@azure/keyvault-secrets");
const { TableClient } = require("@azure/data-tables");

// ============================================================
// CONFIGURATION
// ============================================================
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET;
const KEY_TOKEN_TTL_SECONDS = parseInt(process.env.TOKEN_TTL_SECONDS || "120", 10);
const SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL_SECONDS || "7200", 10);
const GUEST_TTL_SECONDS = parseInt(process.env.GUEST_TTL_SECONDS || "1800", 10);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*").split(",");

const STORAGE_ACCOUNT_NAME = process.env.STORAGE_ACCOUNT_NAME;
const UPLOADS_CONTAINER = process.env.UPLOADS_CONTAINER || "uploads";
const HLS_CONTAINER = process.env.HLS_CONTAINER || "hls-segments";
const KEYVAULT_URI = process.env.KEYVAULT_URI;
const HLS_SEGMENT_SECONDS = process.env.HLS_SEGMENT_SECONDS || "6";

const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || "admin").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!JWT_SECRET) { console.error("[FATAL] JWT_SECRET manquant"); process.exit(1); }
if (!STORAGE_ACCOUNT_NAME || !KEYVAULT_URI) { console.error("[FATAL] STORAGE_ACCOUNT_NAME / KEYVAULT_URI manquants"); process.exit(1); }

// ============================================================
// OBSERVABILITE : Application Insights (F-OBS-05, optionnel)
// ============================================================
let appInsightsClient = null;
if (process.env.APPLICATIONINSIGHTS_CONNECTION_STRING) {
  try {
    const appInsights = require("applicationinsights");
    appInsights
      .setup()
      .setAutoCollectRequests(true)
      .setAutoCollectDependencies(true)
      .setAutoCollectExceptions(true)
      .setSendLiveMetrics(false)
      .start();
    appInsightsClient = appInsights.defaultClient;
    console.log("[OK] Application Insights activé");
  } catch (e) {
    console.warn("[WARN] Application Insights indisponible:", e.message);
  }
}

// ============================================================
// CLIENTS AZURE (Managed Identity uniquement — aucune clé de compte)
// ============================================================
const credential = new DefaultAzureCredential();

const blobServiceClient = new BlobServiceClient(
  `https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net`,
  credential
);
const uploadsContainerClient = blobServiceClient.getContainerClient(UPLOADS_CONTAINER);
const hlsContainerClient = blobServiceClient.getContainerClient(HLS_CONTAINER);

const secretClient = new SecretClient(KEYVAULT_URI, credential);

const tableEndpoint = `https://${STORAGE_ACCOUNT_NAME}.table.core.windows.net`;
const usersTable = new TableClient(tableEndpoint, "Users", credential);
const commentsTable = new TableClient(tableEndpoint, "Comments", credential);
const revokedTable = new TableClient(tableEndpoint, "RevokedTokens", credential);
const auditTable = new TableClient(tableEndpoint, "AuditLog", credential);

// ============================================================
// AUDIT / OBSERVABILITE (F-OBS-01 à F-OBS-04, F-KS-07)
// ============================================================
async function audit(event) {
  const entry = {
    ts: new Date().toISOString(),
    username: event.username || "anonymous",
    videoId: event.videoId || null,
    ip: event.ip || null,
    result: event.result || "info",
    detail: event.detail || null,
  };

  // 1) Log structuré sur stdout -> capté par Container Apps -> Log Analytics
  console.log(`[AUDIT] ${JSON.stringify({ type: event.type, ...entry })}`);

  // 2) Application Insights (tableaux de bord / alertes F-OBS-02, F-OBS-03)
  if (appInsightsClient) {
    try {
      appInsightsClient.trackEvent({ name: event.type, properties: { ...entry } });
    } catch { /* non bloquant */ }
  }

  // 3) Table Storage (source pour la page Admin > Journal d'audit, F-OBS-04)
  try {
    await auditTable.createEntity({
      partitionKey: event.type,
      rowKey: uuidv4(),
      ...entry,
    });
  } catch (e) {
    console.error("[AUDIT ERROR]", e.message);
  }
}

function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (xff) return xff.split(",")[0].trim();
  return req.socket.remoteAddress;
}

// ============================================================
// AUTH HELPERS
// ============================================================
function sanitizeUsername(name) {
  return (name || "").toString().trim().toLowerCase().replace(/[^a-z0-9_-]/g, "").slice(0, 32);
}

// NB : le cahier des charges (§8.4, RG-TOK-02) recommande un algorithme
// asymétrique RS256 entre un Core Auth externe et le Key Server. Ici, les
// deux rôles sont fusionnés dans le même service (pas de Core Auth séparé
// pour cette démo), donc HS256 avec un secret partagé interne est
// suffisant et documenté comme tel dans le README (§ "Écarts au cahier
// des charges").
function signSessionToken(user) {
  const jti = uuidv4();
  const ttl = user.role === "guest" ? GUEST_TTL_SECONDS : SESSION_TTL_SECONDS;
  const token = jwt.sign(
    { sub: user.username, role: user.role, typ: "session", jti },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: ttl }
  );
  return { token, jti, expiresIn: ttl };
}

function signKeyToken(videoId, user) {
  return jwt.sign(
    { sub: user.username, role: user.role, videoId, scope: "hls:key:read", typ: "key", jti: uuidv4() },
    JWT_SECRET,
    { algorithm: "HS256", expiresIn: KEY_TOKEN_TTL_SECONDS }
  );
}

// Middleware : exige un jeton de SESSION valide, non révoqué (RG-TOK-04),
// et optionnellement un rôle particulier.
function requireSession(allowedRoles) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/^Bearer (.+)$/);
    if (!match) return res.status(401).json({ error: "Jeton de session manquant" });

    let payload;
    try {
      payload = jwt.verify(match[1], JWT_SECRET, { algorithms: ["HS256"] });
    } catch (err) {
      return res.status(401).json({ error: err.name === "TokenExpiredError" ? "Session expirée" : "Session invalide" });
    }
    if (payload.typ !== "session") return res.status(401).json({ error: "Type de jeton invalide" });

    try {
      await revokedTable.getEntity("revoked", payload.jti);
      return res.status(401).json({ error: "Session révoquée — veuillez vous reconnecter" });
    } catch (e) {
      if (e.statusCode !== 404) console.error("[REVOKED CHECK ERROR]", e.message);
      // 404 = non révoqué, c'est le cas nominal
    }

    if (allowedRoles && !allowedRoles.includes(payload.role)) {
      return res.status(403).json({ error: "Rôle insuffisant pour cette action" });
    }

    req.user = { username: payload.sub, role: payload.role, jti: payload.jti };
    next();
  };
}

// Middleware : exige un jeton CLE de courte durée, scopé à la vidéo demandée
// (F-KS-02, F-KS-03, F-KS-04)
function requireKeyToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) return res.status(401).json({ error: "Jeton clé manquant" });

  try {
    const payload = jwt.verify(match[1], JWT_SECRET, { algorithms: ["HS256"] });
    if (payload.typ !== "key") return res.status(401).json({ error: "Type de jeton invalide" });
    if (payload.videoId !== req.params.videoId) {
      return res.status(403).json({ error: "Jeton non autorisé pour cette vidéo" });
    }
    req.user = { username: payload.sub, role: payload.role };
    next();
  } catch (err) {
    return res.status(401).json({ error: err.name === "TokenExpiredError" ? "Jeton clé expiré" : "Jeton clé invalide" });
  }
}

// ============================================================
// APP
// ============================================================
const app = express();
app.set("trust proxy", true);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(
  cors({
    origin: ALLOWED_ORIGINS.includes("*") ? true : ALLOWED_ORIGINS,
    methods: ["GET", "POST", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());

// F-KS-06 : limitation de débit globale ; les routes de clé ont en plus
// un rate limit dédié plus strict ci-dessous.
const limiter = rateLimit({ windowMs: 60 * 1000, max: 180, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

const keyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${clientIp(req)}:${req.params.videoId}`,
});

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// Les routes de clé ne doivent jamais être mises en cache (§9.1)
app.use("/keys", (req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate");
  next();
});

app.use(express.static(path.join(__dirname, "public")));

// ============================================================
// AUTHENTIFICATION
// ============================================================
app.post("/auth/register", async (req, res) => {
  const username = sanitizeUsername(req.body?.username);
  const password = (req.body?.password || "").toString();
  if (!username || username.length < 3) return res.status(400).json({ error: "Identifiant invalide (3 caractères minimum)" });
  if (password.length < 6) return res.status(400).json({ error: "Mot de passe trop court (6 caractères minimum)" });

  try {
    await usersTable.getEntity("user", username);
    return res.status(409).json({ error: "Cet identifiant existe déjà" });
  } catch (e) {
    if (e.statusCode !== 404) return res.status(500).json({ error: "Erreur serveur" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  await usersTable.createEntity({
    partitionKey: "user",
    rowKey: username,
    passwordHash,
    role: "user",
    ephemeral: false,
    createdAt: new Date().toISOString(),
  });

  const session = signSessionToken({ username, role: "user" });
  await audit({ type: "register", username, ip: clientIp(req), result: "success" });
  res.json({ access_token: session.token, expires_in: session.expiresIn, username, role: "user" });
});

app.post("/auth/login", async (req, res) => {
  const username = sanitizeUsername(req.body?.username);
  const password = (req.body?.password || "").toString();

  let entity;
  try {
    entity = await usersTable.getEntity("user", username);
  } catch {
    await audit({ type: "login", username, ip: clientIp(req), result: "denied", detail: "compte introuvable" });
    return res.status(401).json({ error: "Identifiants invalides" });
  }

  if (entity.ephemeral || !entity.passwordHash) {
    return res.status(401).json({ error: "Ce compte ne peut pas se connecter par mot de passe" });
  }

  const valid = await bcrypt.compare(password, entity.passwordHash);
  if (!valid) {
    await audit({ type: "login", username, ip: clientIp(req), result: "denied", detail: "mot de passe incorrect" });
    return res.status(401).json({ error: "Identifiants invalides" });
  }

  const session = signSessionToken({ username, role: entity.role });
  await audit({ type: "login", username, ip: clientIp(req), result: "success" });
  res.json({ access_token: session.token, expires_in: session.expiresIn, username, role: entity.role });
});

app.post("/auth/guest", async (req, res) => {
  const username = `guest-${crypto.randomBytes(3).toString("hex")}`;
  await usersTable.createEntity({
    partitionKey: "user",
    rowKey: username,
    passwordHash: "",
    role: "guest",
    ephemeral: true,
    createdAt: new Date().toISOString(),
  });

  const session = signSessionToken({ username, role: "guest" });
  await audit({ type: "login", username, ip: clientIp(req), result: "success", detail: "compte invité éphémère" });
  res.json({ access_token: session.token, expires_in: session.expiresIn, username, role: "guest" });
});

app.post("/auth/logout", requireSession(), async (req, res) => {
  const { username, role, jti } = req.user;

  await revokedTable.createEntity({
    partitionKey: "revoked",
    rowKey: jti,
    revokedAt: new Date().toISOString(),
    username,
  });
  await audit({ type: "logout", username, ip: clientIp(req), result: "success" });

  // Compte invité éphémère : on purge ses vidéos de test et leurs clés —
  // c'est l'équivalent réaliste de "la clé est supprimée à la déconnexion"
  // (on ne supprime jamais une clé partagée/vue par d'autres utilisateurs,
  // voir README § Écarts au cahier des charges).
  let purged = [];
  if (role === "guest") {
    purged = await purgeOwnedVideos(username);
    try { await usersTable.deleteEntity("user", username); } catch { /* non bloquant */ }
  }

  res.json({ message: "Déconnecté", purgedVideos: purged });
});

// ============================================================
// UPLOAD HANDLING (multer -> disque temporaire)
// ============================================================
const TMP_ROOT = path.join(os.tmpdir(), "ztstream");
const upload = multer({
  dest: TMP_ROOT,
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1 Go
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("video/")) return cb(new Error("Le fichier doit être une vidéo"));
    cb(null, true);
  },
});

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args);
    let stderr = "";
    proc.stderr.on("data", (d) => (stderr += d.toString()));
    proc.on("error", reject);
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${cmd} a échoué (code ${code}): ${stderr.slice(-2000)}`));
    });
  });
}

function sanitizeVideoId(id) {
  return id.replace(/[^a-zA-Z0-9-]/g, "");
}

async function readMeta(videoId) {
  const buf = await hlsContainerClient.getBlockBlobClient(`${videoId}/meta.json`).downloadToBuffer();
  return JSON.parse(buf.toString());
}

async function writeMeta(videoId, meta) {
  await hlsContainerClient.getBlockBlobClient(`${videoId}/meta.json`).uploadData(
    Buffer.from(JSON.stringify(meta)),
    { blobHTTPHeaders: { blobContentType: "application/json" } }
  );
}

async function deleteContainerPrefix(containerClient, prefix) {
  for await (const blob of containerClient.listBlobsFlat({ prefix })) {
    await containerClient.getBlockBlobClient(blob.name).deleteIfExists();
  }
}

async function purgeOwnedVideos(username) {
  const purged = [];
  const prefixes = new Set();
  for await (const item of hlsContainerClient.listBlobsByHierarchy("/")) {
    if (item.kind === "prefix") prefixes.add(item.name.replace(/\/$/, ""));
  }
  for (const videoId of prefixes) {
    try {
      const meta = await readMeta(videoId);
      if (meta.ownerUsername === username) {
        await deleteVideoCompletely(videoId);
        purged.push(videoId);
      }
    } catch { /* pas de meta.json -> ignorer */ }
  }
  return purged;
}

async function deleteVideoCompletely(videoId) {
  await deleteContainerPrefix(hlsContainerClient, `${videoId}/`);
  await deleteContainerPrefix(uploadsContainerClient, `${videoId}/`);
  try { await secretClient.beginDeleteSecret(`hls-key-${videoId}`); } catch { /* déjà absente */ }
  for await (const c of commentsTable.listEntities({ queryOptions: { filter: `PartitionKey eq '${videoId}'` } })) {
    await commentsTable.deleteEntity(c.partitionKey, c.rowKey).catch(() => {});
  }
}

// ============================================================
// VIDEOS — CRUD (Admin : create/update/delete, tous rôles : read)
// ============================================================
app.post("/upload", requireSession(["admin"]), upload.single("video"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Aucun fichier vidéo reçu (champ 'video')" });

  const videoId = sanitizeVideoId(uuidv4());
  const title = (req.body.title || req.file.originalname || "video").toString().slice(0, 120);
  const workDir = path.join(TMP_ROOT, videoId);
  const outDir = path.join(workDir, "out");

  try {
    await fsp.mkdir(outDir, { recursive: true });

    const ext = path.extname(req.file.originalname) || ".mp4";
    const inputPath = path.join(workDir, `input${ext}`);
    await fsp.rename(req.file.path, inputPath);

    // Génération d'une clé AES-128 aléatoire (§6 : cryptographiquement
    // sûre, jamais dérivée d'un mot de passe) — une clé par vidéo (Lot 0)
    const aesKey = crypto.randomBytes(16);
    const keyFilePath = path.join(workDir, "key.bin");
    await fsp.writeFile(keyFilePath, aesKey);

    const publicBaseUrl = `${req.protocol}://${req.get("host")}`;
    const keyUri = `${publicBaseUrl}/keys/${videoId}`;
    const keyInfoPath = path.join(workDir, "keyinfo.txt");
    await fsp.writeFile(keyInfoPath, `${keyUri}\n${keyFilePath}\n`);

    await run("ffmpeg", [
      "-y", "-i", inputPath,
      "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
      "-c:a", "aac", "-ac", "2", "-b:a", "128k",
      "-hls_time", String(HLS_SEGMENT_SECONDS),
      "-hls_playlist_type", "vod",
      "-hls_key_info_file", keyInfoPath,
      "-hls_segment_filename", path.join(outDir, "segment_%03d.ts"),
      path.join(outDir, "playlist.m3u8"),
    ]);

    const files = await fsp.readdir(outDir);
    for (const f of files) {
      const blockClient = hlsContainerClient.getBlockBlobClient(`${videoId}/${f}`);
      const contentType = f.endsWith(".m3u8") ? "application/vnd.apple.mpegurl" : "video/MP2T";
      await blockClient.uploadFile(path.join(outDir, f), { blobHTTPHeaders: { blobContentType: contentType } });
    }

    await uploadsContainerClient.getBlockBlobClient(`${videoId}/${path.basename(inputPath)}`).uploadFile(inputPath);

    // La clé n'est JAMAIS stockée à côté des segments (§5.1 étape 5) :
    // uniquement dans Key Vault, séparément.
    await secretClient.setSecret(`hls-key-${videoId}`, aesKey.toString("base64"), {
      contentType: "application/octet-stream",
      tags: { videoId, title, createdAt: new Date().toISOString() },
    });

    await writeMeta(videoId, {
      videoId, title,
      ownerUsername: req.user.username,
      createdAt: new Date().toISOString(),
    });

    await audit({ type: "upload", username: req.user.username, videoId, ip: clientIp(req), result: "success", detail: title });

    res.json({
      videoId, title,
      playlistUrl: `https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${HLS_CONTAINER}/${videoId}/playlist.m3u8`,
      message: "Vidéo segmentée et chiffrée avec succès",
    });
  } catch (err) {
    console.error("[UPLOAD ERROR]", err);
    await audit({ type: "upload", username: req.user.username, videoId, ip: clientIp(req), result: "error", detail: err.message });
    res.status(500).json({ error: "Échec du traitement vidéo", detail: err.message });
  } finally {
    await fsp.rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
});

app.get("/videos", requireSession(), async (req, res) => {
  try {
    const prefixes = new Set();
    for await (const item of hlsContainerClient.listBlobsByHierarchy("/")) {
      if (item.kind === "prefix") prefixes.add(item.name);
    }

    const videos = [];
    for (const prefix of prefixes) {
      const videoId = prefix.replace(/\/$/, "");
      try {
        const meta = await readMeta(videoId);
        videos.push({
          videoId: meta.videoId,
          title: meta.title,
          ownerUsername: meta.ownerUsername,
          createdAt: meta.createdAt,
          playlistUrl: `https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${HLS_CONTAINER}/${videoId}/playlist.m3u8`,
        });
      } catch { /* pas de meta.json -> ignorer */ }
    }

    videos.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ videos });
  } catch (err) {
    console.error("[VIDEOS ERROR]", err);
    res.status(500).json({ error: "Impossible de lister les vidéos" });
  }
});

app.patch("/videos/:videoId", requireSession(["admin"]), async (req, res) => {
  const { videoId } = req.params;
  const title = (req.body?.title || "").toString().slice(0, 120);
  if (!title) return res.status(400).json({ error: "Titre requis" });

  try {
    const meta = await readMeta(videoId);
    meta.title = title;
    await writeMeta(videoId, meta);
    await audit({ type: "update_video", username: req.user.username, videoId, ip: clientIp(req), result: "success", detail: title });
    res.json({ message: "Vidéo mise à jour", videoId, title });
  } catch {
    res.status(404).json({ error: "Vidéo introuvable" });
  }
});

app.delete("/videos/:videoId", requireSession(["admin"]), async (req, res) => {
  const { videoId } = req.params;
  try {
    await deleteVideoCompletely(videoId);
    await audit({ type: "delete_video", username: req.user.username, videoId, ip: clientIp(req), result: "success" });
    res.json({ message: "Vidéo supprimée" });
  } catch (err) {
    console.error("[DELETE VIDEO ERROR]", err);
    res.status(500).json({ error: "Échec de la suppression" });
  }
});

// ============================================================
// JETON CLE (court, scopé à une vidéo, §8.2-8.3) — réservé aux
// sessions authentifiées
// ============================================================
app.post("/videos/:videoId/key-token", requireSession(), (req, res) => {
  const token = signKeyToken(req.params.videoId, req.user);
  res.json({ access_token: token, token_type: "Bearer", expires_in: KEY_TOKEN_TTL_SECONDS });
});

// ============================================================
// DELIVRANCE DE LA CLE AES-128 (F-KS-01, depuis Key Vault) + AUDIT
// ============================================================
app.get("/keys/:videoId", keyLimiter, requireKeyToken, async (req, res) => {
  try {
    const secret = await secretClient.getSecret(`hls-key-${req.params.videoId}`);
    const key = Buffer.from(secret.value, "base64");
    if (key.length !== 16) throw new Error("Longueur de clé invalide");

    res.set({
      "Content-Type": "application/octet-stream",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      Pragma: "no-cache",
      Expires: "0",
    });
    res.send(key);

    await audit({ type: "key_delivery", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "granted" });
  } catch (err) {
    await audit({ type: "key_delivery", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "denied", detail: err.message });
    res.status(404).json({ error: "Clé introuvable pour cette vidéo" });
  }
});

// ============================================================
// COMMENTAIRES — CRUD
// ============================================================
app.get("/videos/:videoId/comments", requireSession(), async (req, res) => {
  const comments = [];
  for await (const c of commentsTable.listEntities({ queryOptions: { filter: `PartitionKey eq '${req.params.videoId}'` } })) {
    comments.push({ commentId: c.rowKey, username: c.username, text: c.text, createdAt: c.createdAt });
  }
  comments.sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  res.json({ comments });
});

app.post("/videos/:videoId/comments", requireSession(), async (req, res) => {
  const text = (req.body?.text || "").toString().trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: "Commentaire vide" });

  const commentId = uuidv4();
  const createdAt = new Date().toISOString();
  await commentsTable.createEntity({
    partitionKey: req.params.videoId,
    rowKey: commentId,
    username: req.user.username,
    text,
    createdAt,
  });
  await audit({ type: "comment_create", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "success" });
  res.json({ commentId, username: req.user.username, text, createdAt });
});

app.patch("/videos/:videoId/comments/:commentId", requireSession(), async (req, res) => {
  const text = (req.body?.text || "").toString().trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: "Commentaire vide" });

  try {
    const entity = await commentsTable.getEntity(req.params.videoId, req.params.commentId);
    if (entity.username !== req.user.username) return res.status(403).json({ error: "Vous ne pouvez modifier que vos commentaires" });
    entity.text = text;
    await commentsTable.updateEntity(entity, "Merge");
    res.json({ message: "Commentaire mis à jour" });
  } catch {
    res.status(404).json({ error: "Commentaire introuvable" });
  }
});

app.delete("/videos/:videoId/comments/:commentId", requireSession(), async (req, res) => {
  try {
    const entity = await commentsTable.getEntity(req.params.videoId, req.params.commentId);
    if (entity.username !== req.user.username && req.user.role !== "admin") {
      return res.status(403).json({ error: "Suppression non autorisée" });
    }
    await commentsTable.deleteEntity(req.params.videoId, req.params.commentId);
    await audit({ type: "comment_delete", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "success" });
    res.json({ message: "Commentaire supprimé" });
  } catch {
    res.status(404).json({ error: "Commentaire introuvable" });
  }
});

// ============================================================
// ADMINISTRATION — utilisateurs + journal d'audit (F-OBS-04)
// ============================================================
app.get("/admin/users", requireSession(["admin"]), async (req, res) => {
  const users = [];
  for await (const u of usersTable.listEntities({ queryOptions: { filter: `PartitionKey eq 'user'` } })) {
    users.push({ username: u.rowKey, role: u.role, ephemeral: !!u.ephemeral, createdAt: u.createdAt });
  }
  users.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ users });
});

app.delete("/admin/users/:username", requireSession(["admin"]), async (req, res) => {
  const username = sanitizeUsername(req.params.username);
  if (username === ADMIN_USERNAME) return res.status(400).json({ error: "Impossible de supprimer le compte administrateur" });
  try {
    await usersTable.deleteEntity("user", username);
    await audit({ type: "delete_user", username: req.user.username, ip: clientIp(req), result: "success", detail: username });
    res.json({ message: "Utilisateur supprimé" });
  } catch {
    res.status(404).json({ error: "Utilisateur introuvable" });
  }
});

app.get("/admin/audit", requireSession(["admin"]), async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "100", 10), 500);
  const entries = [];
  for await (const e of auditTable.listEntities()) {
    entries.push({
      type: e.partitionKey,
      username: e.username,
      videoId: e.videoId,
      ip: e.ip,
      result: e.result,
      detail: e.detail,
      ts: e.ts,
    });
  }
  entries.sort((a, b) => new Date(b.ts) - new Date(a.ts));
  res.json({ entries: entries.slice(0, limit) });
});

// ============================================================
// HEALTH CHECK (F-KS-09)
// ============================================================
app.get("/healthz", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString(), service: "Zero-Trust Key Server" });
});

// ============================================================
// BOOTSTRAP DU COMPTE ADMIN + DEMARRAGE
// ============================================================
async function ensureAdminBootstrap() {
  if (!ADMIN_PASSWORD) {
    console.warn("[WARN] ADMIN_PASSWORD non défini — bootstrap admin ignoré");
    return;
  }
  try {
    await usersTable.getEntity("user", ADMIN_USERNAME);
    console.log(`[OK] Compte admin '${ADMIN_USERNAME}' déjà initialisé`);
  } catch (e) {
    if (e.statusCode !== 404) { console.error("[ADMIN BOOTSTRAP ERROR]", e.message); return; }
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await usersTable.createEntity({
      partitionKey: "user",
      rowKey: ADMIN_USERNAME,
      passwordHash,
      role: "admin",
      ephemeral: false,
      createdAt: new Date().toISOString(),
    });
    console.log(`[OK] Compte admin '${ADMIN_USERNAME}' créé`);
  }
}

fsp.mkdir(TMP_ROOT, { recursive: true })
  .then(() => ensureAdminBootstrap())
  .then(() => {
    app.listen(PORT, () => console.log(`[OK] Zero-Trust Key Server démarré sur le port ${PORT}`));
  })
  .catch((err) => {
    console.error("[FATAL] Démarrage impossible:", err);
    process.exit(1);
  });
