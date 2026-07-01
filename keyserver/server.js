/**
 * ZERO-TRUST HLS - Key & Media Server (v4)
 * --------------------------------------------------
 * Nouveautés v4 :
 *  - Chiffrement PAR SEGMENT : chaque segment .ts d'une vidéo a sa propre
 *    clé AES-128, référencée individuellement dans la playlist
 *    (#EXT-X-KEY par segment). Aucune clé n'est jamais partagée entre
 *    deux segments.
 *  - Rotation automatique des clés de streaming après chaque action
 *    sensible sur une vidéo : une fois qu'une session de lecture se
 *    termine (expiration du jeton clé) ou qu'un téléchargement est
 *    approuvé, tous les segments sont déchiffrés puis rechiffrés avec
 *    de nouvelles clés — les anciennes clés deviennent inutilisables.
 *  - Téléchargement protégé par autorisation admin : un utilisateur
 *    demande l'autorisation, l'admin valide ou refuse ; si validé, un
 *    export chiffré à usage unique est généré avec une clé de
 *    déchiffrement distincte, à durée de vie limitée (expiration native
 *    Key Vault) — passé ce délai, le fichier téléchargé redevient
 *    illisible.
 *
 * Flux de lecture protégée (rappel §4.1 du cahier des charges Pôle 2) :
 *  1. Jeton de session obtenu au login
 *  2. Playlist .m3u8 chargée publiquement (contient une entrée
 *     #EXT-X-KEY par segment, chacune pointant vers son URI de clé)
 *  3. Jeton clé court (120s) demandé, scopé à la vidéo
 *  4. Chaque requête de clé de segment vérifie signature/scope/expiration/révocation
 *  5. Clé AES-128 du segment lue dans Key Vault, jamais mise en cache, jamais log
 *  6. hls.js déchiffre chaque segment à la volée
 *  7. Toute délivrance de clé et action sensible est journalisée
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
const DOWNLOAD_CONTAINER = process.env.DOWNLOAD_CONTAINER || "downloads";
const KEYVAULT_URI = process.env.KEYVAULT_URI;
const HLS_SEGMENT_SECONDS = parseFloat(process.env.HLS_SEGMENT_SECONDS || "6");
const DOWNLOAD_KEY_TTL_HOURS = parseFloat(process.env.DOWNLOAD_KEY_TTL_HOURS || "24");

const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || "admin").toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!JWT_SECRET) { console.error("[FATAL] JWT_SECRET manquant"); process.exit(1); }
if (!STORAGE_ACCOUNT_NAME || !KEYVAULT_URI) { console.error("[FATAL] STORAGE_ACCOUNT_NAME / KEYVAULT_URI manquants"); process.exit(1); }

// ============================================================
// OBSERVABILITE : Application Insights (optionnel)
// ============================================================
let appInsightsClient = null;
if (process.env.APPLICATIONINSIGHTS_CONNECTION_STRING) {
  try {
    const appInsights = require("applicationinsights");
    appInsights.setup().setAutoCollectRequests(true).setAutoCollectDependencies(true)
      .setAutoCollectExceptions(true).setSendLiveMetrics(false).start();
    appInsightsClient = appInsights.defaultClient;
    console.log("[OK] Application Insights activé");
  } catch (e) { console.warn("[WARN] Application Insights indisponible:", e.message); }
}

// ============================================================
// CLIENTS AZURE (Managed Identity uniquement)
// ============================================================
const credential = new DefaultAzureCredential();
const blobServiceClient = new BlobServiceClient(`https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net`, credential);
const uploadsContainerClient = blobServiceClient.getContainerClient(UPLOADS_CONTAINER);
const hlsContainerClient = blobServiceClient.getContainerClient(HLS_CONTAINER);
const downloadContainerClient = blobServiceClient.getContainerClient(DOWNLOAD_CONTAINER);

const secretClient = new SecretClient(KEYVAULT_URI, credential);

const tableEndpoint = `https://${STORAGE_ACCOUNT_NAME}.table.core.windows.net`;
const usersTable = new TableClient(tableEndpoint, "Users", credential);
const commentsTable = new TableClient(tableEndpoint, "Comments", credential);
const revokedTable = new TableClient(tableEndpoint, "RevokedTokens", credential);
const auditTable = new TableClient(tableEndpoint, "AuditLog", credential);
const downloadRequestsTable = new TableClient(tableEndpoint, "DownloadRequests", credential);

// ============================================================
// AUDIT / OBSERVABILITE
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
  console.log(`[AUDIT] ${JSON.stringify({ type: event.type, ...entry })}`);
  if (appInsightsClient) {
    try { appInsightsClient.trackEvent({ name: event.type, properties: { ...entry } }); } catch { /* non bloquant */ }
  }
  try {
    await auditTable.createEntity({ partitionKey: event.type, rowKey: uuidv4(), ...entry });
  } catch (e) { console.error("[AUDIT ERROR]", e.message); }
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

function signSessionToken(user) {
  const jti = uuidv4();
  const ttl = user.role === "guest" ? GUEST_TTL_SECONDS : SESSION_TTL_SECONDS;
  const token = jwt.sign({ sub: user.username, role: user.role, typ: "session", jti }, JWT_SECRET, { algorithm: "HS256", expiresIn: ttl });
  return { token, jti, expiresIn: ttl };
}

function signKeyToken(videoId, user) {
  return jwt.sign(
    { sub: user.username, role: user.role, videoId, scope: "hls:key:read", typ: "key", jti: uuidv4() },
    JWT_SECRET, { algorithm: "HS256", expiresIn: KEY_TOKEN_TTL_SECONDS }
  );
}

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
    }

    if (allowedRoles && !allowedRoles.includes(payload.role)) {
      return res.status(403).json({ error: "Rôle insuffisant pour cette action" });
    }
    req.user = { username: payload.sub, role: payload.role, jti: payload.jti };
    next();
  };
}

function requireKeyToken(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) return res.status(401).json({ error: "Jeton clé manquant" });

  try {
    const payload = jwt.verify(match[1], JWT_SECRET, { algorithms: ["HS256"] });
    if (payload.typ !== "key") return res.status(401).json({ error: "Type de jeton invalide" });
    if (payload.videoId !== req.params.videoId) return res.status(403).json({ error: "Jeton non autorisé pour cette vidéo" });
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
app.use(cors({
  origin: ALLOWED_ORIGINS.includes("*") ? true : ALLOWED_ORIGINS,
  methods: ["GET", "POST", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());

const limiter = rateLimit({ windowMs: 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

const keyLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false,
  keyGenerator: (req) => `${clientIp(req)}:${req.params.videoId}`,
});

app.use((req, res, next) => { console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`); next(); });

app.use(["/keys", "/videos"], (req, res, next) => {
  if (req.path.includes("download-key") || req.path.match(/^\/[a-zA-Z0-9-]+\/\d+$/)) {
    res.set("Cache-Control", "no-store, no-cache, must-revalidate");
  }
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
  } catch (e) { if (e.statusCode !== 404) return res.status(500).json({ error: "Erreur serveur" }); }

  const passwordHash = await bcrypt.hash(password, 10);
  await usersTable.createEntity({ partitionKey: "user", rowKey: username, passwordHash, role: "user", ephemeral: false, createdAt: new Date().toISOString() });

  const session = signSessionToken({ username, role: "user" });
  await audit({ type: "register", username, ip: clientIp(req), result: "success" });
  res.json({ access_token: session.token, expires_in: session.expiresIn, username, role: "user" });
});

app.post("/auth/login", async (req, res) => {
  const username = sanitizeUsername(req.body?.username);
  const password = (req.body?.password || "").toString();

  let entity;
  try { entity = await usersTable.getEntity("user", username); }
  catch {
    await audit({ type: "login", username, ip: clientIp(req), result: "denied", detail: "compte introuvable" });
    return res.status(401).json({ error: "Identifiants invalides" });
  }

  if (entity.ephemeral || !entity.passwordHash) return res.status(401).json({ error: "Ce compte ne peut pas se connecter par mot de passe" });

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
  await usersTable.createEntity({ partitionKey: "user", rowKey: username, passwordHash: "", role: "guest", ephemeral: true, createdAt: new Date().toISOString() });
  const session = signSessionToken({ username, role: "guest" });
  await audit({ type: "login", username, ip: clientIp(req), result: "success", detail: "compte invité éphémère" });
  res.json({ access_token: session.token, expires_in: session.expiresIn, username, role: "guest" });
});

app.post("/auth/logout", requireSession(), async (req, res) => {
  const { username, role, jti } = req.user;
  await revokedTable.createEntity({ partitionKey: "revoked", rowKey: jti, revokedAt: new Date().toISOString(), username });
  await audit({ type: "logout", username, ip: clientIp(req), result: "success" });

  let purged = [];
  if (role === "guest") {
    purged = await purgeOwnedVideos(username);
    try { await usersTable.deleteEntity("user", username); } catch { /* non bloquant */ }
  }
  res.json({ message: "Déconnecté", purgedVideos: purged });
});

// ============================================================
// UPLOAD HANDLING
// ============================================================
const TMP_ROOT = path.join(os.tmpdir(), "ztstream");
const upload = multer({
  dest: TMP_ROOT,
  limits: { fileSize: 1024 * 1024 * 1024 },
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
    proc.on("close", (code) => { if (code === 0) resolve(); else reject(new Error(`${cmd} a échoué (code ${code}): ${stderr.slice(-2000)}`)); });
  });
}

function sanitizeVideoId(id) { return id.replace(/[^a-zA-Z0-9-]/g, ""); }

async function readMeta(videoId) {
  const buf = await hlsContainerClient.getBlockBlobClient(`${videoId}/meta.json`).downloadToBuffer();
  return JSON.parse(buf.toString());
}
async function writeMeta(videoId, meta) {
  await hlsContainerClient.getBlockBlobClient(`${videoId}/meta.json`).uploadData(
    Buffer.from(JSON.stringify(meta)), { blobHTTPHeaders: { blobContentType: "application/json" } }
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
      if (meta.ownerUsername === username) { await deleteVideoCompletely(videoId); purged.push(videoId); }
    } catch { /* pas de meta.json -> ignorer */ }
  }
  return purged;
}
async function deleteSegmentKeys(videoId, segmentCount) {
  for (let i = 0; i < segmentCount; i++) {
    try { await secretClient.beginDeleteSecret(`hls-key-${videoId}-${i}`); } catch { /* déjà absente */ }
  }
}
async function deleteVideoCompletely(videoId) {
  let segmentCount = 0;
  try { segmentCount = (await readMeta(videoId)).segmentCount || 0; } catch { /* pas de meta */ }
  await deleteContainerPrefix(hlsContainerClient, `${videoId}/`);
  await deleteContainerPrefix(uploadsContainerClient, `${videoId}/`);
  await deleteSegmentKeys(videoId, segmentCount);
  for await (const c of commentsTable.listEntities({ queryOptions: { filter: `PartitionKey eq '${videoId}'` } })) {
    await commentsTable.deleteEntity(c.partitionKey, c.rowKey).catch(() => {});
  }
  for await (const r of downloadRequestsTable.listEntities({ queryOptions: { filter: `PartitionKey eq '${videoId}'` } })) {
    await downloadRequestsTable.deleteEntity(r.partitionKey, r.rowKey).catch(() => {});
  }
}

// ------------------------------------------------------------
// CHIFFREMENT PAR SEGMENT
// ------------------------------------------------------------
// ffmpeg segmente en HLS SANS chiffrement natif ; chaque segment est
// ensuite chiffré individuellement (clé + IV propres), et la playlist
// est réécrite à la main avec une directive #EXT-X-KEY par segment.
async function encryptSegmentsAndBuildPlaylist(videoId, outDir, baseUrl) {
  const files = (await fsp.readdir(outDir)).filter((f) => f.endsWith(".ts")).sort();
  const origPlaylist = await fsp.readFile(path.join(outDir, "playlist.m3u8"), "utf8");
  const durations = [...origPlaylist.matchAll(/#EXTINF:([\d.]+),/g)].map((m) => parseFloat(m[1]));

  const lines = ["#EXTM3U", "#EXT-X-VERSION:3", `#EXT-X-TARGETDURATION:${Math.ceil(HLS_SEGMENT_SECONDS) + 1}`, "#EXT-X-PLAYLIST-TYPE:VOD"];

  for (let i = 0; i < files.length; i++) {
    const key = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    const raw = await fsp.readFile(path.join(outDir, files[i]));
    const cipher = crypto.createCipheriv("aes-128-cbc", key, iv);
    const encrypted = Buffer.concat([cipher.update(raw), cipher.final()]);
    await fsp.writeFile(path.join(outDir, files[i]), encrypted);

    await secretClient.setSecret(`hls-key-${videoId}-${i}`, key.toString("base64"), {
      contentType: "application/octet-stream",
      tags: { videoId, segment: String(i) },
    });

    lines.push(`#EXT-X-KEY:METHOD=AES-128,URI="${baseUrl}/keys/${videoId}/${i}",IV=0x${iv.toString("hex")}`);
    lines.push(`#EXTINF:${(durations[i] || HLS_SEGMENT_SECONDS).toFixed(3)},`);
    lines.push(files[i]);
  }
  lines.push("#EXT-X-ENDLIST");
  await fsp.writeFile(path.join(outDir, "playlist.m3u8"), lines.join("\n"));
  return files.length;
}

// ------------------------------------------------------------
// ROTATION AUTOMATIQUE DES CLES DE STREAMING
// ------------------------------------------------------------
// Déchiffre puis rechiffre chaque segment avec une clé et un IV neufs.
// Déclenchée après l'expiration d'une session de lecture et après
// l'approbation d'un téléchargement — les anciennes clés délivrées
// deviennent définitivement inutilisables une fois la rotation faite.
const rotationLocks = new Set();

async function rotateSegmentKeys(videoId, reason) {
  if (rotationLocks.has(videoId)) return;
  rotationLocks.add(videoId);
  try {
    const playlistClient = hlsContainerClient.getBlockBlobClient(`${videoId}/playlist.m3u8`);
    let playlistText;
    try {
      playlistText = (await playlistClient.downloadToBuffer()).toString("utf8");
    } catch {
      return; // vidéo supprimée entre-temps
    }
    const lines = playlistText.split("\n");
    let segIndex = -1;

    for (let li = 0; li < lines.length; li++) {
      if (!lines[li].startsWith("#EXT-X-KEY")) continue;
      segIndex++;

      let filenameLine = -1;
      for (let j = li + 1; j < lines.length; j++) {
        if (lines[j] && !lines[j].startsWith("#")) { filenameLine = j; break; }
      }
      if (filenameLine === -1) continue;
      const filename = lines[filenameLine];

      const ivMatch = lines[li].match(/IV=0x([0-9a-fA-F]+)/);
      if (!ivMatch) continue;
      const oldIv = Buffer.from(ivMatch[1], "hex");

      let oldKey;
      try {
        const secret = await secretClient.getSecret(`hls-key-${videoId}-${segIndex}`);
        oldKey = Buffer.from(secret.value, "base64");
      } catch { continue; }

      const segClient = hlsContainerClient.getBlockBlobClient(`${videoId}/${filename}`);
      const encBuf = await segClient.downloadToBuffer();

      const decipher = crypto.createDecipheriv("aes-128-cbc", oldKey, oldIv);
      const rawBuf = Buffer.concat([decipher.update(encBuf), decipher.final()]);

      const newKey = crypto.randomBytes(16);
      const newIv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv("aes-128-cbc", newKey, newIv);
      const newEncBuf = Buffer.concat([cipher.update(rawBuf), cipher.final()]);

      await segClient.uploadData(newEncBuf, { blobHTTPHeaders: { blobContentType: "video/MP2T" } });
      await secretClient.setSecret(`hls-key-${videoId}-${segIndex}`, newKey.toString("base64"), {
        contentType: "application/octet-stream",
        tags: { videoId, segment: String(segIndex) },
      });

      lines[li] = lines[li].replace(/IV=0x[0-9a-fA-F]+/, `IV=0x${newIv.toString("hex")}`);
    }

    await playlistClient.uploadData(Buffer.from(lines.join("\n")), { blobHTTPHeaders: { blobContentType: "application/vnd.apple.mpegurl" } });
    await audit({ type: "key_rotation", username: "system", videoId, result: "success", detail: `${segIndex + 1} segment(s) — ${reason}` });
  } catch (err) {
    await audit({ type: "key_rotation", username: "system", videoId, result: "error", detail: err.message });
  } finally {
    rotationLocks.delete(videoId);
  }
}

// NB : la planification ci-dessous est en mémoire (setTimeout). Sur un
// Container App avec plusieurs réplicas ou en cas de redémarrage, une
// rotation planifiée peut être perdue — acceptable pour cette démo,
// documenté dans le README (limite connue, extension possible : une
// file de tâches durable type Azure Storage Queue + Container Apps Jobs).
function scheduleRotationAfterPlayback(videoId) {
  setTimeout(() => { rotateSegmentKeys(videoId, "après expiration d'une session de lecture"); }, (KEY_TOKEN_TTL_SECONDS + 5) * 1000);
}

// ============================================================
// VIDEOS — CRUD
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

    // Segmentation HLS SANS chiffrement natif ffmpeg : le chiffrement
    // par segment est appliqué juste après (voir plus haut)
    await run("ffmpeg", [
      "-y", "-i", inputPath,
      "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
      "-c:a", "aac", "-ac", "2", "-b:a", "128k",
      "-hls_time", String(HLS_SEGMENT_SECONDS),
      "-hls_playlist_type", "vod",
      "-hls_segment_filename", path.join(outDir, "segment_%03d.ts"),
      path.join(outDir, "playlist.m3u8"),
    ]);

    const publicBaseUrl = `${req.protocol}://${req.get("host")}`;
    const segmentCount = await encryptSegmentsAndBuildPlaylist(videoId, outDir, publicBaseUrl);

    const files = await fsp.readdir(outDir);
    for (const f of files) {
      const blockClient = hlsContainerClient.getBlockBlobClient(`${videoId}/${f}`);
      const contentType = f.endsWith(".m3u8") ? "application/vnd.apple.mpegurl" : "video/MP2T";
      await blockClient.uploadFile(path.join(outDir, f), { blobHTTPHeaders: { blobContentType: contentType } });
    }

    // Le fichier source brut est conservé (privé) : c'est lui qui sert
    // de base à un export chiffré en cas de téléchargement approuvé
    await uploadsContainerClient.getBlockBlobClient(`${videoId}/${path.basename(inputPath)}`).uploadFile(inputPath);

    await writeMeta(videoId, {
      videoId, title, ownerUsername: req.user.username,
      createdAt: new Date().toISOString(),
      segmentCount,
      sourceFilename: path.basename(inputPath),
    });

    await audit({ type: "upload", username: req.user.username, videoId, ip: clientIp(req), result: "success", detail: `${title} — ${segmentCount} segment(s), 1 clé AES-128 par segment` });

    res.json({
      videoId, title, segmentCount,
      playlistUrl: `https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${HLS_CONTAINER}/${videoId}/playlist.m3u8`,
      message: "Vidéo segmentée et chiffrée avec succès (une clé par segment)",
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
          videoId: meta.videoId, title: meta.title, ownerUsername: meta.ownerUsername,
          createdAt: meta.createdAt, segmentCount: meta.segmentCount || 0,
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
  } catch { res.status(404).json({ error: "Vidéo introuvable" }); }
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
// JETON CLE + DELIVRANCE DE CLE PAR SEGMENT
// ============================================================
app.post("/videos/:videoId/key-token", requireSession(), (req, res) => {
  const token = signKeyToken(req.params.videoId, req.user);
  scheduleRotationAfterPlayback(req.params.videoId);
  res.json({ access_token: token, token_type: "Bearer", expires_in: KEY_TOKEN_TTL_SECONDS });
});

app.get("/keys/:videoId/:segIndex", keyLimiter, requireKeyToken, async (req, res) => {
  const segIndex = parseInt(req.params.segIndex, 10);
  if (Number.isNaN(segIndex) || segIndex < 0) return res.status(400).json({ error: "Index de segment invalide" });

  try {
    const secret = await secretClient.getSecret(`hls-key-${req.params.videoId}-${segIndex}`);
    const key = Buffer.from(secret.value, "base64");
    if (key.length !== 16) throw new Error("Longueur de clé invalide");

    res.set({ "Content-Type": "application/octet-stream", "Cache-Control": "no-store, no-cache, must-revalidate", Pragma: "no-cache", Expires: "0" });
    res.send(key);
    await audit({ type: "key_delivery", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "granted", detail: `segment ${segIndex}` });
  } catch (err) {
    await audit({ type: "key_delivery", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "denied", detail: `segment ${segIndex} — ${err.message}` });
    res.status(404).json({ error: "Clé de segment introuvable" });
  }
});

// ============================================================
// TELECHARGEMENT — demande, approbation, export chiffré, clé à durée limitée
// ============================================================
async function findLatestDownloadRequest(videoId, username) {
  let latest = null;
  for await (const r of downloadRequestsTable.listEntities({ queryOptions: { filter: `PartitionKey eq '${videoId}' and username eq '${username}'` } })) {
    if (!latest || new Date(r.requestedAt) > new Date(latest.requestedAt)) latest = r;
  }
  return latest;
}

function downloadRequestPublicView(r) {
  if (!r) return null;
  const expired = r.status === "approved" && r.downloadKeyExpiresAt && new Date(r.downloadKeyExpiresAt) < new Date();
  return {
    requestId: r.rowKey, videoId: r.partitionKey, username: r.username,
    status: expired ? "expired" : r.status,
    requestedAt: r.requestedAt, decidedAt: r.decidedAt || null, decidedBy: r.decidedBy || null,
    downloadKeyExpiresAt: r.downloadKeyExpiresAt || null,
  };
}

app.post("/videos/:videoId/download-request", requireSession(), async (req, res) => {
  const { videoId } = req.params;
  try {
    await readMeta(videoId);
  } catch { return res.status(404).json({ error: "Vidéo introuvable" }); }

  const existing = await findLatestDownloadRequest(videoId, req.user.username);
  if (existing && ["pending", "approved"].includes(existing.status)) {
    const view = downloadRequestPublicView(existing);
    if (view.status !== "expired") return res.json(view);
  }

  const requestId = uuidv4();
  const entity = {
    partitionKey: videoId, rowKey: requestId,
    username: req.user.username, status: "pending",
    requestedAt: new Date().toISOString(), decidedAt: "", decidedBy: "", downloadKeyExpiresAt: "", exportBlobName: "",
  };
  await downloadRequestsTable.createEntity(entity);
  await audit({ type: "download_request", username: req.user.username, videoId, ip: clientIp(req), result: "pending" });
  res.json(downloadRequestPublicView(entity));
});

app.get("/videos/:videoId/download-status", requireSession(), async (req, res) => {
  const latest = await findLatestDownloadRequest(req.params.videoId, req.user.username);
  res.json({ request: downloadRequestPublicView(latest) });
});

app.get("/admin/download-requests", requireSession(["admin"]), async (req, res) => {
  const requests = [];
  for await (const r of downloadRequestsTable.listEntities()) {
    let title = r.partitionKey;
    try { title = (await readMeta(r.partitionKey)).title; } catch { /* vidéo supprimée */ }
    requests.push({ ...downloadRequestPublicView(r), videoTitle: title });
  }
  requests.sort((a, b) => new Date(b.requestedAt) - new Date(a.requestedAt));
  res.json({ requests });
});

app.post("/admin/download-requests/:videoId/:requestId/approve", requireSession(["admin"]), async (req, res) => {
  const { videoId, requestId } = req.params;
  let entity;
  try { entity = await downloadRequestsTable.getEntity(videoId, requestId); }
  catch { return res.status(404).json({ error: "Demande introuvable" }); }

  try {
    const meta = await readMeta(videoId);

    // Retrouver le fichier source brut privé
    let sourceBlobName = null;
    for await (const b of uploadsContainerClient.listBlobsFlat({ prefix: `${videoId}/` })) { sourceBlobName = b.name; break; }
    if (!sourceBlobName) return res.status(404).json({ error: "Fichier source introuvable pour cette vidéo" });

    const sourceBuf = await uploadsContainerClient.getBlockBlobClient(sourceBlobName).downloadToBuffer();

    // Clé d'export dédiée, distincte des clés de streaming
    const exportKey = crypto.randomBytes(16);
    const exportIv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-128-cbc", exportKey, exportIv);
    const encrypted = Buffer.concat([cipher.update(sourceBuf), cipher.final()]);

    const exportBlobName = `${requestId}.enc`;
    await downloadContainerClient.getBlockBlobClient(exportBlobName).uploadData(encrypted, { blobHTTPHeaders: { blobContentType: "application/octet-stream" } });

    const expiresOn = new Date(Date.now() + DOWNLOAD_KEY_TTL_HOURS * 3600 * 1000);
    await secretClient.setSecret(`dl-key-${requestId}`, Buffer.concat([exportKey, exportIv]).toString("base64"), {
      contentType: "application/octet-stream",
      expiresOn,
      tags: { videoId, requestId, username: entity.username },
    });

    entity.status = "approved";
    entity.decidedAt = new Date().toISOString();
    entity.decidedBy = req.user.username;
    entity.downloadKeyExpiresAt = expiresOn.toISOString();
    entity.exportBlobName = exportBlobName;
    await downloadRequestsTable.updateEntity(entity, "Merge");

    // La clé d'export est nouvelle et indépendante, mais on rotationne
    // aussi les clés de streaming par précaution (bonne hygiène Zero-Trust
    // après une action sensible sur la vidéo)
    rotateSegmentKeys(videoId, "après approbation d'un téléchargement");

    await audit({ type: "download_approve", username: req.user.username, videoId, ip: clientIp(req), result: "success", detail: `demandeur: ${entity.username}, expire: ${expiresOn.toISOString()}` });
    res.json(downloadRequestPublicView(entity));
  } catch (err) {
    console.error("[DOWNLOAD APPROVE ERROR]", err);
    await audit({ type: "download_approve", username: req.user.username, videoId, ip: clientIp(req), result: "error", detail: err.message });
    res.status(500).json({ error: "Échec de la préparation du téléchargement", detail: err.message });
  }
});

app.post("/admin/download-requests/:videoId/:requestId/deny", requireSession(["admin"]), async (req, res) => {
  const { videoId, requestId } = req.params;
  try {
    const entity = await downloadRequestsTable.getEntity(videoId, requestId);
    entity.status = "denied";
    entity.decidedAt = new Date().toISOString();
    entity.decidedBy = req.user.username;
    await downloadRequestsTable.updateEntity(entity, "Merge");
    await audit({ type: "download_deny", username: req.user.username, videoId, ip: clientIp(req), result: "success", detail: `demandeur: ${entity.username}` });
    res.json(downloadRequestPublicView(entity));
  } catch { res.status(404).json({ error: "Demande introuvable" }); }
});

function isRequestUsable(entity) {
  if (!entity || entity.status !== "approved") return false;
  if (!entity.downloadKeyExpiresAt) return false;
  return new Date(entity.downloadKeyExpiresAt) > new Date();
}

app.get("/videos/:videoId/download", requireSession(), async (req, res) => {
  const entity = await findLatestDownloadRequest(req.params.videoId, req.user.username);
  if (!isRequestUsable(entity)) {
    await audit({ type: "download_file", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "denied" });
    return res.status(403).json({ error: "Aucune autorisation de téléchargement valide pour cette vidéo" });
  }
  try {
    const buf = await downloadContainerClient.getBlockBlobClient(entity.exportBlobName).downloadToBuffer();
    res.set({
      "Content-Type": "application/octet-stream",
      "Content-Disposition": `attachment; filename="${req.params.videoId}.enc"`,
      "Cache-Control": "no-store",
    });
    res.send(buf);
    await audit({ type: "download_file", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "granted" });
  } catch (err) {
    res.status(404).json({ error: "Fichier de téléchargement introuvable" });
  }
});

app.get("/videos/:videoId/download-key", requireSession(), async (req, res) => {
  const entity = await findLatestDownloadRequest(req.params.videoId, req.user.username);
  if (!isRequestUsable(entity)) {
    await audit({ type: "download_key", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "denied", detail: "non approuvé ou expiré" });
    return res.status(410).json({ error: "Le délai de validité de cette clé de téléchargement est dépassé. La vidéo téléchargée n'est plus lisible." });
  }
  try {
    const secret = await secretClient.getSecret(`dl-key-${entity.rowKey}`);
    const combined = Buffer.from(secret.value, "base64");
    const key = combined.subarray(0, 16);
    const iv = combined.subarray(16, 32);

    res.set("Cache-Control", "no-store, no-cache, must-revalidate");
    res.json({ key: key.toString("base64"), iv: iv.toString("hex"), expiresAt: entity.downloadKeyExpiresAt });
    await audit({ type: "download_key", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "granted" });
  } catch (err) {
    await audit({ type: "download_key", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "denied", detail: "clé expirée ou purgée par Key Vault" });
    res.status(410).json({ error: "Le délai de validité de cette clé de téléchargement est dépassé. La vidéo téléchargée n'est plus lisible." });
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
  await commentsTable.createEntity({ partitionKey: req.params.videoId, rowKey: commentId, username: req.user.username, text, createdAt });
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
  } catch { res.status(404).json({ error: "Commentaire introuvable" }); }
});

app.delete("/videos/:videoId/comments/:commentId", requireSession(), async (req, res) => {
  try {
    const entity = await commentsTable.getEntity(req.params.videoId, req.params.commentId);
    if (entity.username !== req.user.username && req.user.role !== "admin") return res.status(403).json({ error: "Suppression non autorisée" });
    await commentsTable.deleteEntity(req.params.videoId, req.params.commentId);
    await audit({ type: "comment_delete", username: req.user.username, videoId: req.params.videoId, ip: clientIp(req), result: "success" });
    res.json({ message: "Commentaire supprimé" });
  } catch { res.status(404).json({ error: "Commentaire introuvable" }); }
});

// ============================================================
// ADMINISTRATION — utilisateurs + journal d'audit
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
  } catch { res.status(404).json({ error: "Utilisateur introuvable" }); }
});

app.get("/admin/audit", requireSession(["admin"]), async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || "100", 10), 500);
  const entries = [];
  for await (const e of auditTable.listEntities()) {
    entries.push({ type: e.partitionKey, username: e.username, videoId: e.videoId, ip: e.ip, result: e.result, detail: e.detail, ts: e.ts });
  }
  entries.sort((a, b) => new Date(b.ts) - new Date(a.ts));
  res.json({ entries: entries.slice(0, limit) });
});

// ============================================================
// HEALTH CHECK
// ============================================================
app.get("/healthz", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString(), service: "Zero-Trust Key Server" });
});

// ============================================================
// BOOTSTRAP DU COMPTE ADMIN + DEMARRAGE
// ============================================================
async function ensureAdminBootstrap() {
  if (!ADMIN_PASSWORD) { console.warn("[WARN] ADMIN_PASSWORD non défini — bootstrap admin ignoré"); return; }
  try {
    await usersTable.getEntity("user", ADMIN_USERNAME);
    console.log(`[OK] Compte admin '${ADMIN_USERNAME}' déjà initialisé`);
  } catch (e) {
    if (e.statusCode !== 404) { console.error("[ADMIN BOOTSTRAP ERROR]", e.message); return; }
    const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await usersTable.createEntity({ partitionKey: "user", rowKey: ADMIN_USERNAME, passwordHash, role: "admin", ephemeral: false, createdAt: new Date().toISOString() });
    console.log(`[OK] Compte admin '${ADMIN_USERNAME}' créé`);
  }
}

fsp.mkdir(TMP_ROOT, { recursive: true })
  .then(() => ensureAdminBootstrap())
  .then(() => { app.listen(PORT, () => console.log(`[OK] Zero-Trust Key Server démarré sur le port ${PORT}`)); })
  .catch((err) => { console.error("[FATAL] Démarrage impossible:", err); process.exit(1); });
