/**
 * ZERO-TRUST HLS - Key & Media Server
 * --------------------------------------------------
 * - Reçoit l'upload d'une vidéo
 * - La segmente en HLS et chiffre chaque segment en AES-128 via ffmpeg
 * - Stocke les segments dans Azure Blob Storage (Managed Identity)
 * - Stocke la clé AES dans Azure Key Vault (Managed Identity)
 * - Ne sert la clé qu'après vérification d'un token JWT (Zero-Trust)
 *
 * Aucun secret de credentials Azure n'est en dur : tout passe par
 * DefaultAzureCredential (identité managée du Container App).
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

const { DefaultAzureCredential } = require("@azure/identity");
const { BlobServiceClient } = require("@azure/storage-blob");
const { SecretClient } = require("@azure/keyvault-secrets");

// ============================================================
// CONFIGURATION
// ============================================================
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET; // injecté en secret Container App
const TOKEN_TTL_SECONDS = parseInt(process.env.TOKEN_TTL_SECONDS || "120", 10);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "*").split(",");

const STORAGE_ACCOUNT_NAME = process.env.STORAGE_ACCOUNT_NAME;
const UPLOADS_CONTAINER = process.env.UPLOADS_CONTAINER || "uploads";
const HLS_CONTAINER = process.env.HLS_CONTAINER || "hls-segments";
const KEYVAULT_URI = process.env.KEYVAULT_URI; // ex: https://kv-xxxx.vault.azure.net
const HLS_SEGMENT_SECONDS = process.env.HLS_SEGMENT_SECONDS || "6";

if (!JWT_SECRET) {
  console.error("[FATAL] JWT_SECRET manquant");
  process.exit(1);
}
if (!STORAGE_ACCOUNT_NAME || !KEYVAULT_URI) {
  console.error("[FATAL] STORAGE_ACCOUNT_NAME / KEYVAULT_URI manquants");
  process.exit(1);
}

// ============================================================
// CLIENTS AZURE (Managed Identity)
// ============================================================
const credential = new DefaultAzureCredential();

const blobServiceClient = new BlobServiceClient(
  `https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net`,
  credential
);
const uploadsContainerClient = blobServiceClient.getContainerClient(UPLOADS_CONTAINER);
const hlsContainerClient = blobServiceClient.getContainerClient(HLS_CONTAINER);

const secretClient = new SecretClient(KEYVAULT_URI, credential);

// ============================================================
// APP
// ============================================================
const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(
  cors({
    origin: ALLOWED_ORIGINS.includes("*") ? true : ALLOWED_ORIGINS,
    methods: ["GET", "POST"],
  })
);
app.use(express.json());

const limiter = rateLimit({ windowMs: 60 * 1000, max: 120, standardHeaders: true, legacyHeaders: false });
app.use(limiter);

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

app.use(express.static(path.join(__dirname, "public")));

// ============================================================
// UPLOAD HANDLING (multer -> disque temporaire)
// ============================================================
const TMP_ROOT = path.join(os.tmpdir(), "ztstream");
const upload = multer({
  dest: TMP_ROOT,
  limits: { fileSize: 1024 * 1024 * 1024 }, // 1 Go
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("video/")) {
      return cb(new Error("Le fichier doit être une vidéo"));
    }
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
  // Les noms de secrets Key Vault n'acceptent que [0-9a-zA-Z-]
  return id.replace(/[^a-zA-Z0-9-]/g, "");
}

// ============================================================
// ENDPOINT : UPLOAD + SEGMENTATION + CHIFFREMENT (100% automatique)
// ============================================================
app.post("/upload", upload.single("video"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: "Aucun fichier vidéo reçu (champ 'video')" });
  }

  const videoId = sanitizeVideoId(uuidv4());
  const title = (req.body.title || req.file.originalname || "video").toString().slice(0, 120);
  const workDir = path.join(TMP_ROOT, videoId);
  const outDir = path.join(workDir, "out");

  try {
    await fsp.mkdir(outDir, { recursive: true });

    // 1) Déplacer le fichier uploadé vers un chemin avec extension correcte
    const ext = path.extname(req.file.originalname) || ".mp4";
    const inputPath = path.join(workDir, `input${ext}`);
    await fsp.rename(req.file.path, inputPath);

    // 2) Générer une clé AES-128 aléatoire (jamais écrite en clair côté client)
    const aesKey = crypto.randomBytes(16);
    const keyFilePath = path.join(workDir, "key.bin");
    await fsp.writeFile(keyFilePath, aesKey);

    // 3) Fichier keyinfo pour ffmpeg : URI publique de la clé + chemin local
    const publicBaseUrl = `${req.protocol}://${req.get("host")}`;
    const keyUri = `${publicBaseUrl}/keys/${videoId}`;
    const keyInfoPath = path.join(workDir, "keyinfo.txt");
    await fsp.writeFile(keyInfoPath, `${keyUri}\n${keyFilePath}\n`);

    // 4) Segmentation + chiffrement HLS AES-128 via ffmpeg
    await run("ffmpeg", [
      "-y",
      "-i", inputPath,
      "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
      "-c:a", "aac", "-ac", "2", "-b:a", "128k",
      "-hls_time", String(HLS_SEGMENT_SECONDS),
      "-hls_playlist_type", "vod",
      "-hls_key_info_file", keyInfoPath,
      "-hls_segment_filename", path.join(outDir, "segment_%03d.ts"),
      path.join(outDir, "playlist.m3u8"),
    ]);

    // 5) Upload des segments + playlist chiffrée vers le storage (public en lecture,
    //    le contenu est chiffré donc inutile de le protéger : seule la CLÉ est protégée)
    const files = await fsp.readdir(outDir);
    for (const f of files) {
      const blockClient = hlsContainerClient.getBlockBlobClient(`${videoId}/${f}`);
      const contentType = f.endsWith(".m3u8")
        ? "application/vnd.apple.mpegurl"
        : "video/MP2T";
      await blockClient.uploadFile(path.join(outDir, f), {
        blobHTTPHeaders: { blobContentType: contentType },
      });
    }

    // 6) Upload de la vidéo source brute (traçabilité) dans le container privé
    await uploadsContainerClient.getBlockBlobClient(`${videoId}/${path.basename(inputPath)}`)
      .uploadFile(inputPath);

    // 7) Stockage de la clé AES dans Key Vault (jamais sur le filesystem du storage)
    await secretClient.setSecret(`hls-key-${videoId}`, aesKey.toString("base64"), {
      contentType: "application/octet-stream",
      tags: { videoId, title, createdAt: new Date().toISOString() },
    });

    // 8) Manifeste léger pour lister les vidéos (titre, date) - pas de secret dedans
    await hlsContainerClient.getBlockBlobClient(`${videoId}/meta.json`).uploadData(
      Buffer.from(JSON.stringify({ videoId, title, createdAt: new Date().toISOString() })),
      { blobHTTPHeaders: { blobContentType: "application/json" } }
    );

    res.json({
      videoId,
      title,
      playlistUrl: `https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${HLS_CONTAINER}/${videoId}/playlist.m3u8`,
      message: "Vidéo segmentée et chiffrée avec succès",
    });
  } catch (err) {
    console.error("[UPLOAD ERROR]", err);
    res.status(500).json({ error: "Échec du traitement vidéo", detail: err.message });
  } finally {
    await fsp.rm(workDir, { recursive: true, force: true }).catch(() => {});
  }
});

// ============================================================
// ENDPOINT : LISTE DES VIDEOS DISPONIBLES
// ============================================================
app.get("/videos", async (req, res) => {
  try {
    const prefixes = new Set();
    for await (const item of hlsContainerClient.listBlobsByHierarchy("/")) {
      if (item.kind === "prefix") prefixes.add(item.name);
    }

    const videos = [];
    for (const prefix of prefixes) {
      const videoId = prefix.replace(/\/$/, "");
      try {
        const metaClient = hlsContainerClient.getBlockBlobClient(`${videoId}/meta.json`);
        const buf = await metaClient.downloadToBuffer();
        const meta = JSON.parse(buf.toString());
        videos.push({
          videoId: meta.videoId,
          title: meta.title,
          createdAt: meta.createdAt,
          playlistUrl: `https://${STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${HLS_CONTAINER}/${videoId}/playlist.m3u8`,
        });
      } catch {
        // pas de meta.json -> on ignore
      }
    }

    videos.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ videos });
  } catch (err) {
    console.error("[VIDEOS ERROR]", err);
    res.status(500).json({ error: "Impossible de lister les vidéos" });
  }
});

// ============================================================
// ENDPOINT : AUTHENTIFICATION - GENERER UN TOKEN
// ============================================================
app.post("/auth/token", (req, res) => {
  const { videoId, userId } = req.body || {};
  if (!videoId || typeof videoId !== "string") {
    return res.status(400).json({ error: "videoId requis" });
  }

  const token = jwt.sign(
    {
      sub: userId || "demo_user",
      videoId,
      scope: "hls:key:read",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS,
    },
    JWT_SECRET,
    { algorithm: "HS256" }
  );

  res.json({ access_token: token, token_type: "Bearer", expires_in: TOKEN_TTL_SECONDS });
});

// ============================================================
// MIDDLEWARE : VERIFICATION DU TOKEN
// ============================================================
function verifyJwtForVideo(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const match = authHeader.match(/^Bearer (.+)$/);
  if (!match) return res.status(401).json({ error: "Token Bearer manquant" });

  try {
    const payload = jwt.verify(match[1], JWT_SECRET, { algorithms: ["HS256"] });
    if (payload.videoId !== req.params.videoId) {
      return res.status(403).json({ error: "Token non autorisé pour cette vidéo" });
    }
    req.tokenPayload = payload;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError") return res.status(401).json({ error: "Token expiré" });
    return res.status(401).json({ error: "Token invalide" });
  }
}

// ============================================================
// ENDPOINT : DELIVRANCE DE LA CLE AES-128 (depuis Key Vault)
// ============================================================
app.get("/keys/:videoId", verifyJwtForVideo, async (req, res) => {
  try {
    const secret = await secretClient.getSecret(`hls-key-${req.params.videoId}`);
    const key = Buffer.from(secret.value, "base64");
    if (key.length !== 16) return res.status(500).json({ error: "Clé invalide" });

    res.set({
      "Content-Type": "application/octet-stream",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      Pragma: "no-cache",
      Expires: "0",
    });
    res.send(key);
  } catch (err) {
    console.error("[KEY ERROR]", err.message);
    res.status(404).json({ error: "Clé introuvable pour cette vidéo" });
  }
});

// ============================================================
// ENDPOINT : HEALTH CHECK
// ============================================================
app.get("/healthz", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString(), service: "Zero-Trust Key Server" });
});

// ============================================================
// DEMARRAGE
// ============================================================
fsp.mkdir(TMP_ROOT, { recursive: true }).then(() => {
  app.listen(PORT, () => {
    console.log(`[OK] Zero-Trust Key Server démarré sur le port ${PORT}`);
  });
});
