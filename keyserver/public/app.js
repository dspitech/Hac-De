const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");
const dropzoneText = document.getElementById("dropzoneText");
const titleInput = document.getElementById("titleInput");
const uploadForm = document.getElementById("uploadForm");
const uploadBtn = document.getElementById("uploadBtn");
const pipeline = document.getElementById("pipeline");
const pipelineLabel = document.getElementById("pipelineLabel");
const pipelinePct = document.getElementById("pipelinePct");
const uploadBarFill = document.getElementById("uploadBarFill");
const segmentChain = document.getElementById("segmentChain");
const uploadLog = document.getElementById("uploadLog");
const videoList = document.getElementById("videoList");
const apiStatus = document.getElementById("apiStatus");
const playerTitle = document.getElementById("playerTitle");
const videoEl = document.getElementById("video");

let selectedFile = null;
let segmentTimer = null;

// ---------------------------------------------------------------
// Health check
// ---------------------------------------------------------------
async function checkHealth() {
  try {
    const res = await fetch("/healthz");
    if (!res.ok) throw new Error();
    apiStatus.classList.add("ok");
    apiStatus.classList.remove("bad");
    apiStatus.innerHTML = `<span class="dot"></span> serveur en ligne`;
  } catch {
    apiStatus.classList.add("bad");
    apiStatus.innerHTML = `<span class="dot"></span> serveur injoignable`;
  }
}
checkHealth();
setInterval(checkHealth, 20000);

// ---------------------------------------------------------------
// Dropzone
// ---------------------------------------------------------------
["dragenter", "dragover"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  })
);
["dragleave", "drop"].forEach((evt) =>
  dropzone.addEventListener(evt, (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
  })
);
dropzone.addEventListener("drop", (e) => {
  const file = e.dataTransfer.files[0];
  if (file) setFile(file);
});
fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) setFile(fileInput.files[0]);
});

function setFile(file) {
  selectedFile = file;
  dropzoneText.textContent = `${file.name} — ${(file.size / 1024 / 1024).toFixed(1)} Mo`;
  uploadBtn.disabled = false;
}

// ---------------------------------------------------------------
// Upload + segment-chain animation
// ---------------------------------------------------------------
function buildSegmentChain(count) {
  segmentChain.innerHTML = "";
  for (let i = 0; i < count; i++) {
    const s = document.createElement("div");
    s.className = "segment";
    segmentChain.appendChild(s);
  }
}

function startEncryptionAnimation() {
  const segments = Array.from(segmentChain.children);
  let i = 0;
  segmentTimer = setInterval(() => {
    if (i >= segments.length) i = 0; // boucle pendant le traitement serveur
    segments[i].classList.add("locked");
    i++;
  }, 220);
}

function stopEncryptionAnimation() {
  clearInterval(segmentTimer);
}

uploadForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!selectedFile) return;

  uploadBtn.disabled = true;
  pipeline.hidden = false;
  uploadLog.hidden = true;
  buildSegmentChain(24);
  pipelineLabel.textContent = "Téléversement…";
  pipelinePct.textContent = "0%";
  uploadBarFill.style.width = "0%";

  const formData = new FormData();
  formData.append("video", selectedFile);
  if (titleInput.value.trim()) formData.append("title", titleInput.value.trim());

  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/upload");

  xhr.upload.addEventListener("progress", (evt) => {
    if (!evt.lengthComputable) return;
    const pct = Math.round((evt.loaded / evt.total) * 100);
    uploadBarFill.style.width = pct + "%";
    pipelinePct.textContent = pct + "%";
    if (pct >= 100) {
      pipelineLabel.textContent = "Segmentation & chiffrement AES‑128…";
      startEncryptionAnimation();
    }
  });

  xhr.onload = () => {
    stopEncryptionAnimation();
    uploadBtn.disabled = false;
    uploadLog.hidden = false;

    try {
      const data = JSON.parse(xhr.responseText);
      if (xhr.status >= 200 && xhr.status < 300) {
        Array.from(segmentChain.children).forEach((s) => s.classList.add("locked"));
        pipelineLabel.textContent = "Terminé";
        uploadLog.className = "log success";
        uploadLog.textContent = `✓ ${data.message} — videoId: ${data.videoId}`;
        loadVideos();
        resetForm();
      } else {
        uploadLog.className = "log error";
        uploadLog.textContent = `✗ ${data.error || "Erreur inconnue"}`;
      }
    } catch {
      uploadLog.className = "log error";
      uploadLog.textContent = `✗ Erreur serveur (HTTP ${xhr.status})`;
    }
  };

  xhr.onerror = () => {
    stopEncryptionAnimation();
    uploadBtn.disabled = false;
    uploadLog.hidden = false;
    uploadLog.className = "log error";
    uploadLog.textContent = "✗ Échec réseau pendant le téléversement";
  };

  xhr.send(formData);
});

function resetForm() {
  selectedFile = null;
  fileInput.value = "";
  titleInput.value = "";
  dropzoneText.textContent = "Glissez un fichier ici, ou cliquez pour parcourir";
  uploadBtn.disabled = true;
}

// ---------------------------------------------------------------
// Bibliothèque de vidéos
// ---------------------------------------------------------------
async function loadVideos() {
  try {
    const res = await fetch("/videos");
    const data = await res.json();
    videoList.innerHTML = "";

    if (!data.videos || data.videos.length === 0) {
      videoList.innerHTML = `<li class="empty">Aucune vidéo pour l'instant — téléversez-en une.</li>`;
      return;
    }

    data.videos.forEach((v) => {
      const li = document.createElement("li");
      li.className = "video-item";
      li.innerHTML = `
        <div>
          <div class="vt">${escapeHtml(v.title)}</div>
          <div class="vd">${new Date(v.createdAt).toLocaleString("fr-FR")}</div>
        </div>
        <div class="vd">▶ lire</div>
      `;
      li.addEventListener("click", () => playVideo(v));
      videoList.appendChild(li);
    });
  } catch {
    videoList.innerHTML = `<li class="empty">Erreur lors du chargement des vidéos.</li>`;
  }
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

document.getElementById("refreshBtn").addEventListener("click", loadVideos);
loadVideos();

// ---------------------------------------------------------------
// Lecture protégée (hls.js + clé via JWT)
// ---------------------------------------------------------------
let hls = null;

async function playVideo(v) {
  playerTitle.textContent = v.title;

  // 1) obtenir un jeton JWT propre à cette vidéo
  const tokenRes = await fetch("/auth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ videoId: v.videoId }),
  });
  const tokenData = await tokenRes.json();
  const token = tokenData.access_token;

  if (hls) {
    hls.destroy();
    hls = null;
  }

  if (Hls.isSupported()) {
    hls = new Hls({
      xhrSetup: (xhr, url) => {
        // Seules les requêtes vers /keys/ reçoivent le jeton — la playlist
        // et les segments restent accessibles publiquement (ils sont chiffrés).
        if (url.includes("/keys/")) {
          xhr.setRequestHeader("Authorization", `Bearer ${token}`);
        }
      },
    });
    hls.loadSource(v.playlistUrl);
    hls.attachMedia(videoEl);
    hls.on(Hls.Events.MANIFEST_PARSED, () => videoEl.play().catch(() => {}));
  } else if (videoEl.canPlayType("application/vnd.apple.mpegurl")) {
    videoEl.src = v.playlistUrl;
    videoEl.play().catch(() => {});
  }
}
