const http = require("http");
const crypto = require("crypto");

const DRIVE_FILE_NAME = "zreo-password-backup.json";
const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.appdata";
const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
const DRIVE_FILES_URL = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files";
const TOKEN_FILE_NAME = "google-drive-token.json";
const CONFIG_FILE_NAME = "google-drive-config.json";
const STATE_FILE_NAME = "google-drive-sync-state.json";
const OAUTH_WAIT_TIMEOUT_MS = 2 * 60 * 1000;
const GOOGLE_REQUEST_TIMEOUT_MS = 20 * 1000;
const BUILTIN_CONFIG = loadBuiltinConfig();

let tokenState = null;
let tokenFilePath = "";
let configState = null;
let configFilePath = "";
let syncState = null;
let syncStateFilePath = "";

async function getClientId(app) {
  await loadConfigState(app);
  return process.env.GOOGLE_DRIVE_CLIENT_ID || BUILTIN_CONFIG.clientId || configState?.clientId || "";
}

async function getClientSecret(app) {
  await loadConfigState(app);
  return process.env.GOOGLE_DRIVE_CLIENT_SECRET || BUILTIN_CONFIG.clientSecret || configState?.clientSecret || "";
}

async function isConfigured(app) {
  return Boolean(await getClientId(app) && await getClientSecret(app));
}

async function getStatus(app) {
  await loadTokenState(app);
  await loadSyncState(app);
  let remote = null;
  if (tokenState?.accessToken) {
    remote = await getRemoteState(app).catch((error) => ({
      ok: false,
      message: error.message
    }));
  }
  return {
    configured: await isConfigured(app),
    connected: Boolean(tokenState?.accessToken),
    expiresAt: tokenState?.expiresAt || null,
    hasRefreshToken: Boolean(tokenState?.refreshToken),
    hasClientSecret: Boolean(await getClientSecret(app)),
    clientIdSource: process.env.GOOGLE_DRIVE_CLIENT_ID ? "env" : BUILTIN_CONFIG.clientId ? "built-in" : configState?.clientId ? "saved" : "",
    sync: syncState || {},
    remote
  };
}

async function connect(app, shell) {
  const clientId = await getClientId(app);
  const clientSecret = await getClientSecret(app);
  if (!clientId || !clientSecret) {
    return {
      ok: false,
      reason: "missing-client-id",
      message: "缺少 Google OAuth Client ID 或 Client Secret，无法连接 Google Drive。"
    };
  }

  const verifier = base64Url(crypto.randomBytes(32));
  const challenge = base64Url(crypto.createHash("sha256").update(verifier).digest());
  const state = base64Url(crypto.randomBytes(16));
  const callback = await createCallbackServer(state);
  const authUrl = new URL(GOOGLE_AUTH_URL);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", callback.redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", DRIVE_SCOPE);
  authUrl.searchParams.set("access_type", "offline");
  authUrl.searchParams.set("prompt", "consent");
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("state", state);

  await shell.openExternal(authUrl.toString());

  try {
    const code = await callback.waitForCode;
    const token = await exchangeCodeForToken(clientId, clientSecret, code, callback.redirectUri, verifier);
    await setTokenState(app, token);
    return { ok: true, status: await getStatus(app) };
  } finally {
    callback.close();
  }
}

async function disconnect(app) {
  await loadTokenState(app);
  tokenState = null;
  const filePath = getTokenFilePath(app);
  try {
    await require("fs/promises").unlink(filePath);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
  return { ok: true, status: await getStatus(app) };
}

async function uploadBackup(app, content) {
  const accessToken = await getAccessToken(app);
  const existing = await findBackupFile(accessToken);
  if (existing) {
    const updated = await updateFile(accessToken, existing.id, content);
    await saveSyncState(app, {
      fileId: existing.id,
      lastUploadAt: new Date().toISOString(),
      remoteModifiedTime: updated.modifiedTime || existing.modifiedTime || ""
    });
    return { ok: true, fileId: existing.id, action: "updated", sync: syncState };
  }
  const created = await createFile(accessToken, content);
  await saveSyncState(app, {
    fileId: created.id,
    lastUploadAt: new Date().toISOString(),
    remoteModifiedTime: created.modifiedTime || ""
  });
  return { ok: true, fileId: created.id, action: "created", sync: syncState };
}

async function downloadBackup(app, fileId = "") {
  const accessToken = await getAccessToken(app);
  const existing = fileId ? await getFileMetadata(accessToken, fileId) : await findBackupFile(accessToken);
  if (!existing) {
    return { ok: false, reason: "not-found", message: "Google Drive 中没有找到同步备份。" };
  }
  const response = await fetchWithTimeout(`${DRIVE_FILES_URL}/${existing.id}?alt=media`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  await assertOk(response, "下载 Google Drive 备份失败");
  return {
    ok: true,
    content: await response.text(),
    fileId: existing.id,
    remoteModifiedTime: existing.modifiedTime || "",
    sync: syncState
  };
}

async function markDownloaded(app, info = {}) {
  await saveSyncState(app, {
    fileId: String(info.fileId || ""),
    lastDownloadAt: new Date().toISOString(),
    remoteModifiedTime: String(info.remoteModifiedTime || "")
  });
  return { ok: true, sync: syncState };
}

async function getRemoteState(app) {
  const accessToken = await getAccessToken(app);
  const existing = await findBackupFile(accessToken);
  if (!existing) {
    return { ok: true, exists: false };
  }
  return {
    ok: true,
    exists: true,
    fileId: existing.id,
    modifiedTime: existing.modifiedTime || ""
  };
}

async function listBackups(app) {
  const accessToken = await getAccessToken(app);
  const url = new URL(DRIVE_FILES_URL);
  url.searchParams.set("spaces", "appDataFolder");
  url.searchParams.set("fields", "files(id,name,mimeType,size,createdTime,modifiedTime)");
  url.searchParams.set("q", "'appDataFolder' in parents and trashed=false");
  url.searchParams.set("orderBy", "modifiedTime desc");
  const response = await fetchWithTimeout(url, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  await assertOk(response, "查询 Google Drive 备份列表失败");
  const data = await response.json();
  const files = Array.isArray(data.files) ? data.files : [];
  return {
    ok: true,
    files: files.map((file) => ({
      id: String(file.id || ""),
      name: String(file.name || ""),
      mimeType: String(file.mimeType || ""),
      size: file.size ? Number(file.size) : null,
      createdTime: String(file.createdTime || ""),
      modifiedTime: String(file.modifiedTime || "")
    }))
  };
}

async function getAccessToken(app) {
  await loadTokenState(app);
  if (!tokenState?.accessToken) {
    throw new Error("Google Drive 尚未连接");
  }
  if (Date.now() < tokenState.expiresAt - 60 * 1000) {
    return tokenState.accessToken;
  }
  if (!tokenState.refreshToken) {
    throw new Error("Google Drive 登录已过期，请重新连接");
  }
  const token = await refreshAccessToken(await getClientId(app), await getClientSecret(app), tokenState.refreshToken);
  await setTokenState(app, { ...token, refresh_token: token.refresh_token || tokenState.refreshToken });
  return tokenState.accessToken;
}

async function findBackupFile(accessToken) {
  const query = [
    `name='${DRIVE_FILE_NAME}'`,
    "'appDataFolder' in parents",
    "trashed=false"
  ].join(" and ");
  const url = new URL(DRIVE_FILES_URL);
  url.searchParams.set("spaces", "appDataFolder");
  url.searchParams.set("fields", "files(id,name,modifiedTime)");
  url.searchParams.set("q", query);
  const response = await fetchWithTimeout(url, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  await assertOk(response, "查询 Google Drive 备份失败");
  const data = await response.json();
  return Array.isArray(data.files) && data.files.length ? data.files[0] : null;
}

async function getFileMetadata(accessToken, fileId) {
  const response = await fetchWithTimeout(`${DRIVE_FILES_URL}/${encodeURIComponent(fileId)}?fields=id,name,modifiedTime`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  await assertOk(response, "查询 Google Drive 备份信息失败");
  return response.json();
}

async function createFile(accessToken, content) {
  const boundary = `zreo-${crypto.randomBytes(12).toString("hex")}`;
  const metadata = {
    name: DRIVE_FILE_NAME,
    parents: ["appDataFolder"],
    mimeType: "application/json"
  };
  const body = buildMultipartBody(boundary, metadata, content);
  const response = await fetchWithTimeout(`${DRIVE_UPLOAD_URL}?uploadType=multipart&fields=id,name,modifiedTime`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": `multipart/related; boundary=${boundary}`
    },
    body
  });
  await assertOk(response, "创建 Google Drive 备份失败");
  return response.json();
}

async function updateFile(accessToken, fileId, content) {
  const response = await fetchWithTimeout(`${DRIVE_UPLOAD_URL}/${fileId}?uploadType=media&fields=id,name,modifiedTime`, {
    method: "PATCH",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json"
    },
    body: content
  });
  await assertOk(response, "更新 Google Drive 备份失败");
  return response.json();
}

async function exchangeCodeForToken(clientId, clientSecret, code, redirectUri, verifier) {
  const params = new URLSearchParams({
    client_id: clientId,
    code,
    code_verifier: verifier,
    grant_type: "authorization_code",
    redirect_uri: redirectUri
  });
  if (clientSecret) {
    params.set("client_secret", clientSecret);
  }
  const response = await fetchWithTimeout(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params
  });
  await assertOk(response, "Google OAuth token 交换失败");
  return response.json();
}

async function refreshAccessToken(clientId, clientSecret, refreshToken) {
  const params = new URLSearchParams({
    client_id: clientId,
    refresh_token: refreshToken,
    grant_type: "refresh_token"
  });
  if (clientSecret) {
    params.set("client_secret", clientSecret);
  }
  const response = await fetchWithTimeout(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params
  });
  await assertOk(response, "Google OAuth token 刷新失败");
  return response.json();
}

async function setTokenState(app, token) {
  tokenState = {
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    expiresAt: Date.now() + Number(token.expires_in || 3600) * 1000
  };
  await saveTokenState(app);
}

function buildMultipartBody(boundary, metadata, content) {
  return [
    `--${boundary}`,
    "Content-Type: application/json; charset=UTF-8",
    "",
    JSON.stringify(metadata),
    `--${boundary}`,
    "Content-Type: application/json; charset=UTF-8",
    "",
    content,
    `--${boundary}--`,
    ""
  ].join("\r\n");
}

async function createCallbackServer(expectedState) {
  let server;
  let settled = false;
  let timeoutId;
  const waitForCode = new Promise((resolve, reject) => {
    timeoutId = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("Google OAuth 授权超时，请重新连接"));
    }, OAUTH_WAIT_TIMEOUT_MS);

    server = http.createServer((req, res) => {
      const url = new URL(req.url, "http://127.0.0.1");
      if (url.pathname !== "/oauth2callback") {
        res.writeHead(404);
        res.end("Not found");
        return;
      }
      if (url.searchParams.get("state") !== expectedState) {
        res.writeHead(400);
        res.end("Invalid state");
        if (settled) return;
        settled = true;
        reject(new Error("Google OAuth state 校验失败"));
        return;
      }
      const code = url.searchParams.get("code");
      if (!code) {
        res.writeHead(400);
        res.end("Missing code");
        if (settled) return;
        settled = true;
        reject(new Error("Google OAuth 未返回授权码"));
        return;
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end("<h2>Google Drive 已连接，可以回到小〇密码。</h2>");
      if (settled) return;
      settled = true;
      resolve(code);
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return {
    redirectUri: `http://127.0.0.1:${address.port}/oauth2callback`,
    waitForCode,
    close: () => {
      clearTimeout(timeoutId);
      server.close();
    }
  };
}

async function loadTokenState(app) {
  if (tokenState) return;
  const filePath = getTokenFilePath(app);
  try {
    const raw = await require("fs/promises").readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    tokenState = {
      accessToken: String(parsed.accessToken || ""),
      refreshToken: String(parsed.refreshToken || ""),
      expiresAt: Number(parsed.expiresAt || 0)
    };
  } catch (error) {
    if (error.code !== "ENOENT") {
      tokenState = null;
    }
  }
}

async function saveTokenState(app) {
  if (!tokenState) return;
  const fs = require("fs/promises");
  const filePath = getTokenFilePath(app);
  await fs.mkdir(require("path").dirname(filePath), { recursive: true });
  // 目前先落在 userData，下一步可替换为 macOS Keychain / Windows Credential Manager。
  await fs.writeFile(filePath, `${JSON.stringify(tokenState, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

function getTokenFilePath(app) {
  if (!tokenFilePath) {
    tokenFilePath = require("path").join(app.getPath("userData"), TOKEN_FILE_NAME);
  }
  return tokenFilePath;
}

async function loadConfigState(app) {
  if (configState) return;
  const filePath = getConfigFilePath(app);
  try {
    const raw = await require("fs/promises").readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    configState = {
      clientId: String(parsed.clientId || "").trim(),
      clientSecret: String(parsed.clientSecret || "").trim()
    };
  } catch (error) {
    configState = { clientId: "", clientSecret: "" };
  }
}

function getConfigFilePath(app) {
  if (!configFilePath) {
    configFilePath = require("path").join(app.getPath("userData"), CONFIG_FILE_NAME);
  }
  return configFilePath;
}

async function loadSyncState(app) {
  if (syncState) return;
  const filePath = getSyncStateFilePath(app);
  try {
    const raw = await require("fs/promises").readFile(filePath, "utf8");
    const parsed = JSON.parse(raw);
    syncState = {
      fileId: String(parsed.fileId || ""),
      lastUploadAt: String(parsed.lastUploadAt || ""),
      lastDownloadAt: String(parsed.lastDownloadAt || ""),
      remoteModifiedTime: String(parsed.remoteModifiedTime || "")
    };
  } catch (error) {
    syncState = {};
  }
}

async function saveSyncState(app, nextState) {
  await loadSyncState(app);
  syncState = { ...syncState, ...nextState };
  const fs = require("fs/promises");
  const filePath = getSyncStateFilePath(app);
  await fs.mkdir(require("path").dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, `${JSON.stringify(syncState, null, 2)}\n`, "utf8");
}

function getSyncStateFilePath(app) {
  if (!syncStateFilePath) {
    syncStateFilePath = require("path").join(app.getPath("userData"), STATE_FILE_NAME);
  }
  return syncStateFilePath;
}

function loadBuiltinConfig() {
  const configs = [
    "./google-oauth-private.cjs",
    "./google-oauth-config.cjs"
  ];
  for (const configPath of configs) {
    try {
      const config = require(configPath);
      const clientId = String(config.clientId || "").trim();
      const clientSecret = String(config.clientSecret || "").trim();
      if (clientId || clientSecret) {
        return { clientId, clientSecret };
      }
    } catch {
      // 私有配置文件不存在时使用下一层配置。
    }
  }
  return { clientId: "", clientSecret: "" };
}

async function assertOk(response, message) {
  if (response.ok) return;
  const detail = await response.text();
  throw new Error(`${message}: ${response.status} ${detail}`);
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), GOOGLE_REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

function base64Url(buffer) {
  return buffer.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

module.exports = {
  getStatus,
  connect,
  disconnect,
  getRemoteState,
  listBackups,
  markDownloaded,
  uploadBackup,
  downloadBackup
};
