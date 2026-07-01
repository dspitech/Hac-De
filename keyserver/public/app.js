// ============================================================
// ETAT & UTILITAIRES
// ============================================================
const state = {
  token: localStorage.getItem("zt_token") || null,
  username: localStorage.getItem("zt_username") || null,
  role: localStorage.getItem("zt_role") || null,
  currentVideo: null,
  videosCache: [],
};

function saveSession(data) {
  state.token = data.access_token;
  state.username = data.username;
  state.role = data.role;
  localStorage.setItem("zt_token", state.token);
  localStorage.setItem("zt_username", state.username);
  localStorage.setItem("zt_role", state.role);
}

function clearSession() {
  state.token = null; state.username = null; state.role = null;
  localStorage.removeItem("zt_token");
  localStorage.removeItem("zt_username");
  localStorage.removeItem("zt_role");
}

async function api(pathname, opts = {}) {
  const headers = Object.assign({}, opts.headers || {});
  if (state.token) headers["Authorization"] = `Bearer ${state.token}`;
  if (opts.body && !(opts.body instanceof FormData)) headers["Content-Type"] = "application/json";

  const res = await fetch(pathname, { ...opts, headers });
  if (res.status === 401 && pathname !== "/auth/login") {
    clearSession();
    renderAuthState();
    throw new Error("Session expirée, reconnectez-vous");
  }
  const isJson = (res.headers.get("content-type") || "").includes("application/json");
  const data = isJson ? await res.json() : await res.blob();
  if (!res.ok) throw new Error((data && data.error) || `Erreur HTTP ${res.status}`);
  return data;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

// ============================================================
// HEALTH CHECK
// ============================================================
const apiStatus = document.getElementById("apiStatus");
async function checkHealth() {
  try {
    const res = await fetch("/healthz");
    if (!res.ok) throw new Error();
    apiStatus.classList.add("ok"); apiStatus.classList.remove("bad");
    apiStatus.innerHTML = `<span class="dot"></span> serveur en ligne`;
  } catch {
    apiStatus.classList.add("bad"); apiStatus.classList.remove("ok");
    apiStatus.innerHTML = `<span class="dot"></span> serveur injoignable`;
  }
}
checkHealth();
setInterval(checkHealth, 20000);

// ============================================================
// AUTH UI : tabs login/register
// ============================================================
document.querySelectorAll("[data-authtab]").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("[data-authtab]").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const target = btn.dataset.authtab;
    document.getElementById("loginForm").hidden = target !== "login";
    document.getElementById("registerForm").hidden = target !== "register";
  });
});

const authLog = document.getElementById("authLog");
function showAuthError(msg) {
  authLog.hidden = false;
  authLog.className = "log error";
  authLog.textContent = `✗ ${msg}`;
}

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value;
  try {
    const data = await api("/auth/login", { method: "POST", body: JSON.stringify({ username, password }) });
    saveSession(data);
    onAuthenticated();
  } catch (err) { showAuthError(err.message); }
});

document.getElementById("registerForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("registerUsername").value.trim();
  const password = document.getElementById("registerPassword").value;
  try {
    const data = await api("/auth/register", { method: "POST", body: JSON.stringify({ username, password }) });
    saveSession(data);
    onAuthenticated();
  } catch (err) { showAuthError(err.message); }
});

document.getElementById("guestBtn").addEventListener("click", async () => {
  try {
    const data = await api("/auth/guest", { method: "POST", body: JSON.stringify({}) });
    saveSession(data);
    onAuthenticated();
  } catch (err) { showAuthError(err.message); }
});

document.getElementById("logoutBtn").addEventListener("click", async () => {
  try { await api("/auth/logout", { method: "POST" }); } catch { /* on déconnecte quand même */ }
  clearSession();
  renderAuthState();
});

// ============================================================
// NAV TABS (Bibliothèque / Administration)
// ============================================================
document.querySelectorAll(".navlink").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".navlink").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    document.querySelectorAll(".tabpanel").forEach((p) => (p.hidden = true));
    document.getElementById(`tab-${btn.dataset.tab}`).hidden = false;
    if (btn.dataset.tab === "admin") { loadAdminVideos(); loadUsers(); loadAudit(); loadDownloadRequests(); }
  });
});

// ============================================================
// RENDU DE L'ETAT D'AUTHENTIFICATION
// ============================================================
const ROLE_LABELS = { admin: "Professionnel", user: "Utilisateur final", guest: "Invité" };

function renderAuthState() {
  const loggedIn = !!state.token;
  document.getElementById("heroSection").hidden = loggedIn;
  document.getElementById("marketingSection").hidden = loggedIn;
  document.getElementById("appLayout").hidden = !loggedIn;
  document.getElementById("navTabs").hidden = !loggedIn;
  document.getElementById("userBox").hidden = !loggedIn;

  if (loggedIn) {
    document.getElementById("usernameLabel").textContent = state.username;
    const badge = document.getElementById("roleBadge");
    badge.textContent = ROLE_LABELS[state.role] || state.role;
    badge.className = `role-badge role-${state.role}`;
    document.getElementById("navAdminTab").hidden = state.role !== "admin";
  }
}

function onAuthenticated() {
  renderAuthState();
  loadVideos();
}

// ============================================================
// BIBLIOTHEQUE DE VIDEOS
// ============================================================
const videoList = document.getElementById("videoList");

async function loadVideos() {
  try {
    const data = await api("/videos");
    state.videosCache = data.videos || [];
    renderVideoList();
  } catch (err) {
    videoList.innerHTML = `<li class="empty">${escapeHtml(err.message)}</li>`;
  }
}

function renderVideoList() {
  if (state.videosCache.length === 0) {
    videoList.innerHTML = `<li class="empty">Aucune vidéo pour l'instant.</li>`;
    return;
  }
  videoList.innerHTML = "";
  state.videosCache.forEach((v) => {
    const li = document.createElement("li");
    li.className = "video-item";
    li.innerHTML = `
      <div>
        <div class="vt">${escapeHtml(v.title)}</div>
        <div class="vd">par ${escapeHtml(v.ownerUsername || "?")} · ${new Date(v.createdAt).toLocaleString("fr-FR")}</div>
      </div>
      <div class="vd">▶ lire</div>`;
    li.addEventListener("click", () => playVideo(v));
    videoList.appendChild(li);
  });
}

document.getElementById("refreshBtn").addEventListener("click", loadVideos);

// ============================================================
// LECTURE PROTEGEE (hls.js + jeton clé scopé à la vidéo)
// ============================================================
const playerTitle = document.getElementById("playerTitle");
const videoEl = document.getElementById("video");
let hls = null;

async function playVideo(v) {
  state.currentVideo = v;
  playerTitle.textContent = v.title;

  let keyTokenData;
  try {
    keyTokenData = await api(`/videos/${v.videoId}/key-token`, { method: "POST" });
  } catch (err) {
    playerTitle.textContent = `Erreur : ${err.message}`;
    return;
  }
  const keyToken = keyTokenData.access_token;

  if (hls) { hls.destroy(); hls = null; }

  if (Hls.isSupported()) {
    hls = new Hls({
      xhrSetup: (xhr, url) => {
        if (url.includes("/keys/")) xhr.setRequestHeader("Authorization", `Bearer ${keyToken}`);
      },
    });
    hls.loadSource(v.playlistUrl);
    hls.attachMedia(videoEl);
    hls.on(Hls.Events.MANIFEST_PARSED, () => videoEl.play().catch(() => { }));
  } else if (videoEl.canPlayType("application/vnd.apple.mpegurl")) {
    videoEl.src = v.playlistUrl;
    videoEl.play().catch(() => { });
  }

  document.getElementById("commentsBox").hidden = false;
  loadComments(v.videoId);
  downloadBtn.hidden = false;
}

// ============================================================
// COMMENTAIRES — CRUD
// ============================================================
const commentList = document.getElementById("commentList");

async function loadComments(videoId) {
  try {
    const data = await api(`/videos/${videoId}/comments`);
    commentList.innerHTML = "";
    if (data.comments.length === 0) {
      commentList.innerHTML = `<li class="empty">Aucun commentaire — soyez le premier.</li>`;
      return;
    }
    data.comments.forEach((c) => {
      const li = document.createElement("li");
      li.className = "comment-item";
      const canDelete = c.username === state.username || state.role === "admin";
      li.innerHTML = `
        <div class="comment-head">
          <strong>${escapeHtml(c.username)}</strong>
          <span class="vd">${new Date(c.createdAt).toLocaleString("fr-FR")}</span>
          ${canDelete ? `<button class="btn-ghost tiny del-comment">supprimer</button>` : ""}
        </div>
        <div class="comment-text">${escapeHtml(c.text)}</div>`;
      if (canDelete) {
        li.querySelector(".del-comment").addEventListener("click", async () => {
          try {
            await api(`/videos/${videoId}/comments/${c.commentId}`, { method: "DELETE" });
            loadComments(videoId);
          } catch (err) { alert(err.message); }
        });
      }
      commentList.appendChild(li);
    });
  } catch (err) {
    commentList.innerHTML = `<li class="empty">${escapeHtml(err.message)}</li>`;
  }
}

document.getElementById("commentForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!state.currentVideo) return;
  const input = document.getElementById("commentInput");
  const text = input.value.trim();
  if (!text) return;
  try {
    await api(`/videos/${state.currentVideo.videoId}/comments`, { method: "POST", body: JSON.stringify({ text }) });
    input.value = "";
    loadComments(state.currentVideo.videoId);
  } catch (err) { alert(err.message); }
});

// ============================================================
// ADMIN : UPLOAD (drag & drop + animation de chiffrement segment par segment)
// ============================================================
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

let selectedFile = null;
let segmentTimer = null;

["dragenter", "dragover"].forEach((evt) => dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add("dragover"); }));
["dragleave", "drop"].forEach((evt) => dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove("dragover"); }));
dropzone.addEventListener("drop", (e) => { const f = e.dataTransfer.files[0]; if (f) setFile(f); });
fileInput.addEventListener("change", () => { if (fileInput.files[0]) setFile(fileInput.files[0]); });

function setFile(file) {
  selectedFile = file;
  dropzoneText.textContent = `${file.name} — ${(file.size / 1024 / 1024).toFixed(1)} Mo`;
  uploadBtn.disabled = false;
}

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
    if (i >= segments.length) i = 0;
    segments[i].classList.add("locked");
    i++;
  }, 220);
}
function stopEncryptionAnimation() { clearInterval(segmentTimer); }

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
  if (state.token) xhr.setRequestHeader("Authorization", `Bearer ${state.token}`);

  xhr.upload.addEventListener("progress", (evt) => {
    if (!evt.lengthComputable) return;
    const pct = Math.round((evt.loaded / evt.total) * 100);
    uploadBarFill.style.width = pct + "%";
    pipelinePct.textContent = pct + "%";
    if (pct >= 100) { pipelineLabel.textContent = "Segmentation & chiffrement AES‑128…"; startEncryptionAnimation(); }
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
        loadVideos(); loadAdminVideos();
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

// ============================================================
// ADMIN : GESTION DES VIDEOS (update titre / suppression)
// ============================================================
async function loadAdminVideos() {
  const tbody = document.querySelector("#adminVideoTable tbody");
  tbody.innerHTML = `<tr><td colspan="4">Chargement…</td></tr>`;
  try {
    const data = await api("/videos");
    tbody.innerHTML = "";
    data.videos.forEach((v) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><input type="text" class="text-input small" value="${escapeHtml(v.title)}" data-id="${v.videoId}" /></td>
        <td>${escapeHtml(v.ownerUsername || "?")}</td>
        <td>${new Date(v.createdAt).toLocaleDateString("fr-FR")}</td>
        <td class="row-actions">
          <button class="btn-ghost tiny save-video">enregistrer</button>
          <button class="btn-ghost tiny danger del-video">supprimer</button>
        </td>`;
      tr.querySelector(".save-video").addEventListener("click", async () => {
        const title = tr.querySelector("input").value.trim();
        try { await api(`/videos/${v.videoId}`, { method: "PATCH", body: JSON.stringify({ title }) }); loadVideos(); } catch (err) { alert(err.message); }
      });
      tr.querySelector(".del-video").addEventListener("click", async () => {
        if (!confirm(`Supprimer définitivement "${v.title}" ?`)) return;
        try { await api(`/videos/${v.videoId}`, { method: "DELETE" }); loadAdminVideos(); loadVideos(); } catch (err) { alert(err.message); }
      });
      tbody.appendChild(tr);
    });
    if (data.videos.length === 0) tbody.innerHTML = `<tr><td colspan="4">Aucune vidéo</td></tr>`;
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4">${escapeHtml(err.message)}</td></tr>`;
  }
}

// ============================================================
// ADMIN : UTILISATEURS
// ============================================================
async function loadUsers() {
  const tbody = document.querySelector("#usersTable tbody");
  tbody.innerHTML = `<tr><td colspan="4">Chargement…</td></tr>`;
  try {
    const data = await api("/admin/users");
    tbody.innerHTML = "";
    data.users.forEach((u) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(u.username)}</td>
        <td><span class="role-badge role-${u.role}">${ROLE_LABELS[u.role] || u.role}</span></td>
        <td>${new Date(u.createdAt).toLocaleDateString("fr-FR")}</td>
        <td class="row-actions">${u.username === state.username ? "" : `<button class="btn-ghost tiny danger del-user">supprimer</button>`}</td>`;
      const delBtn = tr.querySelector(".del-user");
      if (delBtn) delBtn.addEventListener("click", async () => {
        if (!confirm(`Supprimer le compte "${u.username}" ?`)) return;
        try { await api(`/admin/users/${u.username}`, { method: "DELETE" }); loadUsers(); } catch (err) { alert(err.message); }
      });
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4">${escapeHtml(err.message)}</td></tr>`;
  }
}

// ============================================================
// ADMIN : JOURNAL D'AUDIT
// ============================================================
async function loadAudit() {
  const tbody = document.querySelector("#auditTable tbody");
  tbody.innerHTML = `<tr><td colspan="6">Chargement…</td></tr>`;
  try {
    const data = await api("/admin/audit?limit=150");
    tbody.innerHTML = "";
    data.entries.forEach((e) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">${new Date(e.ts).toLocaleString("fr-FR")}</td>
        <td>${escapeHtml(e.type)}</td>
        <td>${escapeHtml(e.username)}</td>
        <td class="mono">${escapeHtml(e.videoId || "—")}</td>
        <td class="mono">${escapeHtml(e.ip || "—")}</td>
        <td><span class="result-badge result-${escapeHtml(e.result)}">${escapeHtml(e.result)}</span></td>`;
      tbody.appendChild(tr);
    });
    if (data.entries.length === 0) tbody.innerHTML = `<tr><td colspan="6">Aucun événement</td></tr>`;
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6">${escapeHtml(err.message)}</td></tr>`;
  }
}
document.getElementById("refreshAuditBtn").addEventListener("click", loadAudit);

// ============================================================
// TELECHARGEMENT — popup d'autorisation, statut, admin
// ============================================================
const downloadBtn = document.getElementById("downloadBtn");
const downloadModalOverlay = document.getElementById("downloadModalOverlay");
const downloadModalBody = document.getElementById("downloadModalBody");

function openDownloadModal() {
  downloadModalOverlay.hidden = false;
  downloadModalOverlay.classList.add("active");
}
function closeDownloadModal() {
  downloadModalOverlay.hidden = true;
  downloadModalOverlay.classList.remove("active");
}
document.getElementById("downloadModalClose").addEventListener("click", closeDownloadModal);
downloadModalOverlay.addEventListener("click", (e) => { if (e.target === downloadModalOverlay) closeDownloadModal(); });

function fmtDate(iso) { return iso ? new Date(iso).toLocaleString("fr-FR") : "—"; }

async function refreshDownloadModal() {
  if (!state.currentVideo) return;
  const videoId = state.currentVideo.videoId;
  downloadModalBody.innerHTML = `<h3>Vérification de vos droits…</h3>`;
  openDownloadModal();

  let data;
  try {
    data = await api(`/videos/${videoId}/download-status`);
  } catch (err) {
    downloadModalBody.innerHTML = `<h3>Erreur</h3><p>${escapeHtml(err.message)}</p>`;
    return;
  }
  renderDownloadModal(data.request, videoId);
}

function renderDownloadModal(request, videoId) {
  if (!request || request.status === "denied" || request.status === "expired") {
    const reasonMsg = request && request.status === "denied"
      ? "Votre précédente demande a été refusée par un administrateur."
      : request && request.status === "expired"
        ? "Votre précédente autorisation a expiré : la clé de déchiffrement n'est plus valide."
        : "";
    downloadModalBody.innerHTML = `
      <h3>Accès protégé</h3>
      <p>Vous n'avez pas les droits nécessaires. Cette vidéo est protégée : veuillez demander une
        autorisation de téléchargement à un administrateur.</p>
      ${reasonMsg ? `<p class="modal-note">${escapeHtml(reasonMsg)}</p>` : ""}
      <button class="btn-primary" id="requestAccessBtn">Demander l'autorisation</button>
    `;
    document.getElementById("requestAccessBtn").addEventListener("click", async () => {
      try {
        const req = await api(`/videos/${videoId}/download-request`, { method: "POST" });
        renderDownloadModal(req, videoId);
      } catch (err) { alert(err.message); }
    });
    return;
  }

  if (request.status === "pending") {
    downloadModalBody.innerHTML = `
      <h3>Demande envoyée</h3>
      <p>Votre demande d'autorisation est en attente de validation par un administrateur.</p>
      <p class="modal-note">Demandée le ${fmtDate(request.requestedAt)}</p>
      <button class="btn-outline" id="checkAgainBtn">Vérifier à nouveau</button>
    `;
    document.getElementById("checkAgainBtn").addEventListener("click", refreshDownloadModal);
    return;
  }

  if (request.status === "approved") {
    downloadModalBody.innerHTML = `
      <h3>Autorisation accordée</h3>
      <p>Le fichier est chiffré avec une clé distincte des clés de lecture. Cette clé est valable
        jusqu'au <strong>${fmtDate(request.downloadKeyExpiresAt)}</strong> — passé ce délai, le fichier
        téléchargé ne sera plus lisible, même localement.</p>
      <button class="btn-primary" id="doDownloadBtn">Télécharger le fichier chiffré</button>
      <a class="btn-outline" href="offline-player.html?video=${videoId}" target="_blank" rel="noopener" style="display:block; text-align:center; text-decoration:none; margin-top:10px;">Ouvrir le lecteur hors-ligne</a>
    `;
    document.getElementById("doDownloadBtn").addEventListener("click", () => downloadEncryptedFile(videoId));
    return;
  }

  downloadModalBody.innerHTML = `<h3>Statut inconnu</h3><p>Réessayez plus tard.</p>`;
}

async function downloadEncryptedFile(videoId) {
  try {
    const res = await fetch(`/videos/${videoId}/download`, { headers: { Authorization: `Bearer ${state.token}` } });
    if (!res.ok) { const d = await res.json(); throw new Error(d.error || "Échec du téléchargement"); }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${videoId}.enc`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  } catch (err) { alert(err.message); }
}

downloadBtn.addEventListener("click", refreshDownloadModal);

// ============================================================
// ADMIN : DEMANDES DE TELECHARGEMENT
// ============================================================
async function loadDownloadRequests() {
  const tbody = document.querySelector("#downloadReqTable tbody");
  tbody.innerHTML = `<tr><td colspan="5">Chargement…</td></tr>`;
  try {
    const data = await api("/admin/download-requests");
    tbody.innerHTML = "";
    if (data.requests.length === 0) { tbody.innerHTML = `<tr><td colspan="5">Aucune demande</td></tr>`; return; }
    data.requests.forEach((r) => {
      const tr = document.createElement("tr");
      const statusClass = r.status === "approved" ? "result-success" : r.status === "denied" ? "result-denied" : "";
      const statusBadge = `<span class="result-badge ${statusClass}">${escapeHtml(r.status)}</span>`;
      const actions = r.status === "pending"
        ? `<button class="btn-ghost tiny approve-req">approuver</button> <button class="btn-ghost tiny danger deny-req">refuser</button>`
        : "";
      tr.innerHTML = `
        <td>${escapeHtml(r.videoTitle)}</td>
        <td>${escapeHtml(r.username)}</td>
        <td class="mono">${fmtDate(r.requestedAt)}</td>
        <td>${statusBadge}</td>
        <td class="row-actions">${actions}</td>`;
      const approveBtn = tr.querySelector(".approve-req");
      const denyBtn = tr.querySelector(".deny-req");
      if (approveBtn) approveBtn.addEventListener("click", async () => {
        try { await api(`/admin/download-requests/${r.videoId}/${r.requestId}/approve`, { method: "POST" }); loadDownloadRequests(); } catch (err) { alert(err.message); }
      });
      if (denyBtn) denyBtn.addEventListener("click", async () => {
        try { await api(`/admin/download-requests/${r.videoId}/${r.requestId}/deny`, { method: "POST" }); loadDownloadRequests(); } catch (err) { alert(err.message); }
      });
      tbody.appendChild(tr);
    });
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5">${escapeHtml(err.message)}</td></tr>`;
  }
}
document.getElementById("refreshDownloadReqBtn").addEventListener("click", loadDownloadRequests);

// ============================================================
// DEMARRAGE
// ============================================================
closeDownloadModal();
renderAuthState();
if (state.token) loadVideos();