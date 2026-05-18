const STORAGE_KEY = "zreo-password-vault-v1";
const SESSION_KEY = "zreo-password-session-key";
const SESSION_PASSWORD_KEY = "zreo-password-session-master";
const DEFAULT_CATEGORY = "未分类";

const state = {
  records: [],
  selectedId: null,
  visiblePasswordIds: new Set(),
  lastListClick: { id: null, time: 0 },
  activeCategory: "全部",
  key: null,
  mode: "create"
};

const els = {
  authScreen: document.querySelector("#authScreen"),
  authForm: document.querySelector("#authForm"),
  authTitle: document.querySelector("#authTitle"),
  authDescription: document.querySelector("#authDescription"),
  authSubmitButton: document.querySelector("#authSubmitButton"),
  authMessage: document.querySelector("#authMessage"),
  masterPasswordInput: document.querySelector("#masterPasswordInput"),
  confirmPasswordLabel: document.querySelector("#confirmPasswordLabel"),
  confirmPasswordInput: document.querySelector("#confirmPasswordInput"),
  newItemButton: document.querySelector("#newItemButton"),
  categoryList: document.querySelector("#categoryList"),
  settingsButton: document.querySelector("#settingsButton"),
  exportButton: document.querySelector("#exportButton"),
  importInput: document.querySelector("#importInput"),
  searchInput: document.querySelector("#searchInput"),
  lockButton: document.querySelector("#lockButton"),
  sortSelect: document.querySelector("#sortSelect"),
  totalCount: document.querySelector("#totalCount"),
  weakCount: document.querySelector("#weakCount"),
  duplicateCount: document.querySelector("#duplicateCount"),
  recentCount: document.querySelector("#recentCount"),
  vaultList: document.querySelector("#vaultList"),
  detailPanel: document.querySelector("#detailPanel"),
  itemDialog: document.querySelector("#itemDialog"),
  itemForm: document.querySelector("#itemForm"),
  dialogTitle: document.querySelector("#dialogTitle"),
  closeDialogButton: document.querySelector("#closeDialogButton"),
  cancelButton: document.querySelector("#cancelButton"),
  saveButton: document.querySelector("#saveButton"),
  deleteButton: document.querySelector("#deleteButton"),
  titleInput: document.querySelector("#titleInput"),
  categoryInput: document.querySelector("#categoryInput"),
  categoryOptions: document.querySelector("#categoryOptions"),
  urlInput: document.querySelector("#urlInput"),
  usernameInput: document.querySelector("#usernameInput"),
  loginMethodInput: document.querySelector("#loginMethodInput"),
  passwordInput: document.querySelector("#passwordInput"),
  toggleFormPasswordButton: document.querySelector("#toggleFormPasswordButton"),
  noteInput: document.querySelector("#noteInput"),
  generateButton: document.querySelector("#generateButton"),
  lengthInput: document.querySelector("#lengthInput"),
  lengthValue: document.querySelector("#lengthValue"),
  symbolsInput: document.querySelector("#symbolsInput"),
  settingsDialog: document.querySelector("#settingsDialog"),
  settingsForm: document.querySelector("#settingsForm"),
  closeSettingsButton: document.querySelector("#closeSettingsButton"),
  currentMasterPasswordInput: document.querySelector("#currentMasterPasswordInput"),
  newMasterPasswordInput: document.querySelector("#newMasterPasswordInput"),
  confirmNewMasterPasswordInput: document.querySelector("#confirmNewMasterPasswordInput"),
  changeMasterPasswordButton: document.querySelector("#changeMasterPasswordButton"),
  settingsMessage: document.querySelector("#settingsMessage"),
  toast: document.querySelector("#toast")
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function getStoredVault() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}

function bytesToBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

function createId() {
  if (crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `item-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

async function deriveKey(password, salt) {
  // 使用主密码派生 AES 密钥，主密码本身不落盘。
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 210000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptVault(records, key, salt) {
  // 每次保存都生成新的 IV，避免复用 AES-GCM nonce。
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const payload = {
    version: 1,
    updatedAt: new Date().toISOString(),
    records
  };
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(payload))
  );

  return {
    version: 1,
    algorithm: "AES-GCM",
    kdf: "PBKDF2-SHA256",
    iterations: 210000,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    content: bytesToBase64(encrypted)
  };
}

async function decryptVault(vault, key) {
  const encrypted = base64ToBytes(vault.content);
  const iv = base64ToBytes(vault.iv);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
  return JSON.parse(decoder.decode(decrypted));
}

async function persistRecords() {
  const existing = getStoredVault();
  const salt = existing ? base64ToBytes(existing.salt) : crypto.getRandomValues(new Uint8Array(16));
  const vault = await encryptVault(state.records, state.key, salt);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
}

async function unlockWithPassword(password, options = {}) {
  const storedVault = getStoredVault();
  if (!storedVault) {
    throw new Error("Vault not found");
  }

  const salt = base64ToBytes(storedVault.salt);
  const key = await deriveKey(password, salt);
  const payload = await decryptVault(storedVault, key);
  state.key = key;
  state.records = Array.isArray(payload.records) ? payload.records : [];
  state.selectedId = state.records[0] ? state.records[0].id : null;

  if (options.rememberSession) {
    // 仅保存在当前标签页会话中，刷新可用，关闭标签页后由浏览器清理。
    sessionStorage.setItem(SESSION_KEY, "unlocked");
    sessionStorage.setItem(SESSION_PASSWORD_KEY, password);
  }
}

async function restoreSessionUnlock() {
  const password = sessionStorage.getItem(SESSION_PASSWORD_KEY);
  if (!password || !getStoredVault()) {
    return false;
  }

  try {
    await unlockWithPassword(password, { rememberSession: true });
    els.authScreen.classList.add("is-hidden");
    render();
    return true;
  } catch (error) {
    console.error(error);
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(SESSION_PASSWORD_KEY);
    return false;
  }
}

function showToast(message) {
  els.toast.textContent = message;
  els.toast.classList.add("is-visible");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => {
    els.toast.classList.remove("is-visible");
  }, 2200);
}

function normalizeCategory(value) {
  return value.trim() || DEFAULT_CATEGORY;
}

function scorePassword(password) {
  // MVP 阶段先用轻量规则给出强度反馈，后续可替换为 zxcvbn。
  if (!password) {
    return { score: 0, label: "免密码", className: "muted" };
  }

  let score = Math.min(40, password.length * 2);
  if (/[a-z]/.test(password)) score += 12;
  if (/[A-Z]/.test(password)) score += 12;
  if (/\d/.test(password)) score += 12;
  if (/[^a-zA-Z0-9]/.test(password)) score += 16;
  if (password.length >= 18) score += 8;
  score = Math.min(100, score);

  if (score < 45) return { score, label: "弱", className: "danger" };
  if (score < 75) return { score, label: "中", className: "warning" };
  return { score, label: "强", className: "" };
}

function getLoginMethodMeta(method) {
  const map = {
    password: { label: "账号密码", short: "密码" },
    google: { label: "Google 登录", short: "Google" },
    wechat: { label: "微信登录", short: "微信" },
    github: { label: "GitHub 登录", short: "GitHub" },
    apple: { label: "Apple 登录", short: "Apple" },
    other: { label: "其他方式", short: "其他" }
  };
  return map[method] || map.password;
}

function getRecordLoginMethod(record) {
  return record.loginMethod || (record.password ? "password" : "other");
}

function getFilteredRecords() {
  const keyword = els.searchInput.value.trim().toLowerCase();

  return state.records
    .filter((record) => {
      const categoryMatch = state.activeCategory === "全部" || record.category === state.activeCategory;
      const searchable = [
        record.title,
        record.url,
        record.username,
        record.category,
        getLoginMethodMeta(getRecordLoginMethod(record)).label,
        record.note
      ].join(" ").toLowerCase();
      return categoryMatch && (!keyword || searchable.includes(keyword));
    })
    .sort((a, b) => {
      if (els.sortSelect.value === "titleAsc") {
        return a.title.localeCompare(b.title, "zh-CN");
      }
      if (els.sortSelect.value === "categoryAsc") {
        return a.category.localeCompare(b.category, "zh-CN");
      }
      return new Date(b.updatedAt) - new Date(a.updatedAt);
    });
}

function getCategoryCounts() {
  const counts = new Map();
  counts.set("全部", state.records.length);
  state.records.forEach((record) => {
    counts.set(record.category, (counts.get(record.category) || 0) + 1);
  });
  return counts;
}

function renderCategories() {
  const counts = getCategoryCounts();
  const categories = [...counts.keys()];

  els.categoryList.innerHTML = categories.map((category) => `
    <button class="category-button ${category === state.activeCategory ? "is-active" : ""}" type="button" data-category="${escapeHtml(category)}">
      <span>${escapeHtml(category)}</span>
      <strong>${counts.get(category)}</strong>
    </button>
  `).join("");

  els.categoryOptions.innerHTML = categories
    .filter((category) => category !== "全部")
    .map((category) => `<option value="${escapeHtml(category)}"></option>`)
    .join("");
}

function renderStats() {
  const passwordCounts = new Map();
  state.records.forEach((record) => {
    if (record.password) {
      passwordCounts.set(record.password, (passwordCounts.get(record.password) || 0) + 1);
    }
  });
  const oneWeekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;

  els.totalCount.textContent = state.records.length;
  els.weakCount.textContent = state.records.filter((record) => record.password && scorePassword(record.password).score < 45).length;
  els.duplicateCount.textContent = state.records.filter((record) => passwordCounts.get(record.password) > 1).length;
  els.recentCount.textContent = state.records.filter((record) => new Date(record.updatedAt).getTime() > oneWeekAgo).length;
}

function renderList() {
  const records = getFilteredRecords();
  if (!records.length) {
    els.vaultList.innerHTML = `<div class="empty-list">没有匹配记录。可以新建一条，或者换个关键词试试。</div>`;
    return;
  }

  els.vaultList.innerHTML = records.map((record) => {
    const strength = scorePassword(record.password);
    const loginMethod = getLoginMethodMeta(getRecordLoginMethod(record));
    return `
      <button class="vault-card ${record.id === state.selectedId ? "is-active" : ""}" type="button" data-id="${record.id}" title="双击打开网址">
        <div class="vault-card-title">
          <strong>${escapeHtml(record.title)}</strong>
          <span class="badge ${strength.className}">${escapeHtml(record.password ? strength.label : loginMethod.short)}</span>
        </div>
        <div class="vault-meta">${escapeHtml(record.username || "未设置账号")} · ${escapeHtml(record.category)} · ${escapeHtml(loginMethod.label)}</div>
        <div class="vault-meta">${escapeHtml(getHost(record.url) || "未设置网址")} · ${formatDate(record.updatedAt)}</div>
      </button>
    `;
  }).join("");
}

function renderDetail() {
  const record = state.records.find((item) => item.id === state.selectedId);
  if (!record) {
    els.detailPanel.innerHTML = `
      <div class="empty-detail">
        <div class="empty-icon" aria-hidden="true">⌁</div>
        <h3>选择一条记录</h3>
        <p>查看账号、密码强度、网址与安全备注。数据只在当前浏览器内加密保存。</p>
      </div>
    `;
    return;
  }

  const strength = scorePassword(record.password);
  const loginMethod = getLoginMethodMeta(getRecordLoginMethod(record));
  const isPasswordVisible = state.visiblePasswordIds.has(record.id);
  const passwordText = record.password
    ? (isPasswordVisible ? record.password : "•".repeat(Math.min(record.password.length, 24)))
    : `无密码（${loginMethod.label}）`;
  const passwordAction = record.password ? "toggle-password" : "";
  els.detailPanel.innerHTML = `
    <div class="detail-header">
      <div class="detail-title">
        <p class="eyebrow">${escapeHtml(record.category)}</p>
        <h3>${escapeHtml(record.title)}</h3>
      </div>
      <div class="detail-actions">
        <button class="ghost-button" type="button" data-action="edit">编辑</button>
        <button class="primary-button" type="button" data-action="copy-password">复制密码</button>
      </div>
    </div>

    <div class="detail-fields">
      ${renderField("用户名", record.username || "未设置", "copy-username")}
      ${renderField("登录方式", loginMethod.label, "")}
      ${renderUrlField(record.url)}
      ${renderField("密码", passwordText, passwordAction, true, isPasswordVisible ? "隐藏" : "查看")}
      <div class="field-row">
        <span>强度</span>
        <div>
          <strong>${strength.label}</strong>
          <div class="strength-bar"><div class="strength-fill" style="width: ${strength.score}%"></div></div>
        </div>
      </div>
      <div class="field-row">
        <span>备注</span>
        <p>${escapeHtml(record.note || "无备注")}</p>
      </div>
      <div class="field-row">
        <span>更新时间</span>
        <p>${formatDate(record.updatedAt)}</p>
      </div>
    </div>
  `;
}

function renderField(label, value, action, isCode = false, actionText = "复制") {
  const body = isCode ? `<code>${escapeHtml(value)}</code>` : `<p>${escapeHtml(value)}</p>`;
  const button = action
    ? `<button class="ghost-button" type="button" data-action="${action}">${actionText}</button>`
    : "";
  return `
    <div class="field-row">
      <span>${label}</span>
      ${body}
      ${button}
    </div>
  `;
}

function renderUrlField(url) {
  const safeUrl = url || "";
  const link = safeUrl
    ? `<a href="${escapeHtml(safeUrl)}" target="_blank" rel="noreferrer">${escapeHtml(safeUrl)}</a>`
    : `<p>未设置</p>`;
  return `
    <div class="field-row">
      <span>网址</span>
      ${link}
      <button class="ghost-button" type="button" data-action="copy-url">复制</button>
    </div>
  `;
}

function setFormPasswordVisibility(isVisible) {
  els.passwordInput.type = isVisible ? "text" : "password";
  els.toggleFormPasswordButton.textContent = isVisible ? "🙈" : "👁";
  els.toggleFormPasswordButton.setAttribute("aria-label", isVisible ? "隐藏密码" : "查看密码");
}

function openRecordUrl(record) {
  if (!record.url) {
    showToast("这条记录还没有填写网址");
    return;
  }

  try {
    const url = new URL(record.url);
    window.open(url.href, "_blank", "noopener");
  } catch {
    showToast("网址格式不正确，先编辑一下再跳转");
  }
}

function render() {
  renderCategories();
  renderStats();
  renderList();
  renderDetail();
}

function openCreateDialog() {
  state.mode = "create";
  state.selectedId = state.selectedId || (state.records[0] && state.records[0].id);
  els.dialogTitle.textContent = "新建记录";
  els.deleteButton.hidden = true;
  els.itemForm.reset();
  els.categoryInput.value = state.activeCategory === "全部" ? "" : state.activeCategory;
  els.loginMethodInput.value = "password";
  setFormPasswordVisibility(false);
  els.lengthInput.value = "18";
  els.lengthValue.textContent = "18";
  els.symbolsInput.checked = true;
  els.itemDialog.showModal();
  els.titleInput.focus();
}

function openEditDialog(record) {
  state.mode = "edit";
  els.dialogTitle.textContent = "编辑记录";
  els.deleteButton.hidden = false;
  els.titleInput.value = record.title;
  els.categoryInput.value = record.category;
  els.urlInput.value = record.url || "";
  els.usernameInput.value = record.username || "";
  els.loginMethodInput.value = getRecordLoginMethod(record);
  els.passwordInput.value = record.password || "";
  els.noteInput.value = record.note || "";
  setFormPasswordVisibility(false);
  els.itemDialog.showModal();
  els.titleInput.focus();
}

async function saveRecord(event) {
  event.preventDefault();
  const now = new Date().toISOString();
  const payload = {
    title: els.titleInput.value.trim(),
    category: normalizeCategory(els.categoryInput.value),
    url: els.urlInput.value.trim(),
    username: els.usernameInput.value.trim(),
    loginMethod: els.loginMethodInput.value,
    password: els.passwordInput.value,
    note: els.noteInput.value.trim(),
    updatedAt: now
  };

  if (!payload.title) {
    showToast("标题不能为空");
    return;
  }

  if (state.mode === "edit" && state.selectedId) {
    state.records = state.records.map((record) => (
      record.id === state.selectedId ? { ...record, ...payload } : record
    ));
  } else {
    const record = { id: createId(), createdAt: now, ...payload };
    state.records.unshift(record);
    state.selectedId = record.id;
  }

  await persistRecords();
  els.itemDialog.close();
  render();
  showToast("记录已加密保存");
}

async function deleteSelectedRecord() {
  const record = state.records.find((item) => item.id === state.selectedId);
  if (!record) return;

  const confirmed = window.confirm(`确认删除「${record.title}」？此操作会写入新的本地加密库。`);
  if (!confirmed) return;

  state.records = state.records.filter((item) => item.id !== state.selectedId);
  state.selectedId = state.records[0] ? state.records[0].id : null;
  await persistRecords();
  els.itemDialog.close();
  render();
  showToast("记录已删除");
}

async function changeMasterPassword() {
  els.settingsMessage.textContent = "";
  const currentPassword = els.currentMasterPasswordInput.value;
  const newPassword = els.newMasterPasswordInput.value;
  const confirmPassword = els.confirmNewMasterPasswordInput.value;

  if (!currentPassword || !newPassword || !confirmPassword) {
    els.settingsMessage.textContent = "请完整填写当前主密码和新主密码。";
    return;
  }
  if (newPassword.length < 8) {
    els.settingsMessage.textContent = "新主密码至少 8 位。";
    return;
  }
  if (newPassword !== confirmPassword) {
    els.settingsMessage.textContent = "两次输入的新主密码不一致。";
    return;
  }

  try {
    const storedVault = getStoredVault();
    if (!storedVault) {
      els.settingsMessage.textContent = "还没有可修改的本地密码库。";
      return;
    }

    const currentKey = await deriveKey(currentPassword, base64ToBytes(storedVault.salt));
    await decryptVault(storedVault, currentKey);
    const newSalt = crypto.getRandomValues(new Uint8Array(16));
    state.key = await deriveKey(newPassword, newSalt);
    const nextVault = await encryptVault(state.records, state.key, newSalt);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(nextVault));
    sessionStorage.setItem(SESSION_KEY, "unlocked");
    sessionStorage.setItem(SESSION_PASSWORD_KEY, newPassword);
    els.currentMasterPasswordInput.value = "";
    els.newMasterPasswordInput.value = "";
    els.confirmNewMasterPasswordInput.value = "";
    els.settingsMessage.textContent = "主密码已修改。";
    window.setTimeout(() => {
      els.settingsDialog.close();
      els.settingsMessage.textContent = "";
    }, 700);
    showToast("主密码已修改");
  } catch (error) {
    console.error(error);
    els.settingsMessage.textContent = "当前主密码不正确，修改失败。";
  }
}

function generatePassword() {
  const length = Number(els.lengthInput.value);
  const letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const digits = "23456789";
  const symbols = "!@#$%^&*()-_=+[]{};:,.?";
  const source = letters + digits + (els.symbolsInput.checked ? symbols : "");
  const random = crypto.getRandomValues(new Uint32Array(length));
  const password = [...random].map((value) => source[value % source.length]).join("");
  els.passwordInput.value = password;
  els.loginMethodInput.value = "password";
}

async function copyToClipboard(value, successMessage) {
  if (!value) {
    showToast("没有可复制的内容");
    return;
  }
  await navigator.clipboard.writeText(value);
  showToast(successMessage);
}

async function handleAuth(event) {
  event.preventDefault();
  els.authMessage.textContent = "";
  const password = els.masterPasswordInput.value;
  const confirmPassword = els.confirmPasswordInput.value;
  const storedVault = getStoredVault();

  try {
    if (!storedVault) {
      if (password.length < 8) {
        els.authMessage.textContent = "主密码至少 8 位。";
        return;
      }
      if (password !== confirmPassword) {
        els.authMessage.textContent = "两次输入的主密码不一致。";
        return;
      }

      const salt = crypto.getRandomValues(new Uint8Array(16));
      state.key = await deriveKey(password, salt);
      state.records = createStarterRecords();
      state.selectedId = state.records[0].id;
      const vault = await encryptVault(state.records, state.key, salt);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
      sessionStorage.setItem(SESSION_PASSWORD_KEY, password);
    } else {
      await unlockWithPassword(password, { rememberSession: true });
    }

    sessionStorage.setItem(SESSION_KEY, "unlocked");
    els.authScreen.classList.add("is-hidden");
    els.masterPasswordInput.value = "";
    els.confirmPasswordInput.value = "";
    render();
    showToast("密码库已解锁");
  } catch (error) {
    console.error(error);
    els.authMessage.textContent = "主密码不正确，或者本地数据已损坏。";
  }
}

function configureAuthScreen() {
  const hasVault = Boolean(getStoredVault());
  els.authTitle.textContent = hasVault ? "解锁密码库" : "创建主密码";
  els.authDescription.textContent = hasVault
    ? "输入一次主密码。只要当前页面/标签页不关闭，刷新后会自动恢复。"
    : "主密码用于派生本地加密密钥。它不会上传，也无法找回，请认真记住。";
  els.authSubmitButton.textContent = hasVault ? "解锁进入" : "创建并进入";
  els.confirmPasswordLabel.hidden = hasVault;
  els.confirmPasswordInput.required = !hasVault;
}

function lockVault() {
  state.key = null;
  state.records = [];
  state.selectedId = null;
  state.visiblePasswordIds.clear();
  sessionStorage.removeItem(SESSION_KEY);
  sessionStorage.removeItem(SESSION_PASSWORD_KEY);
  configureAuthScreen();
  els.authScreen.classList.remove("is-hidden");
  els.masterPasswordInput.focus();
}

function exportVault() {
  const vault = localStorage.getItem(STORAGE_KEY);
  if (!vault) {
    showToast("还没有可导出的密码库");
    return;
  }

  const blob = new Blob([vault], { type: "application/json;charset=UTF-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `zreo-password-backup-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
  showToast("已导出加密备份");
}

async function importVault(event) {
  const file = event.target.files[0];
  if (!file) return;

  try {
    const text = await file.text();
    const vault = JSON.parse(text);
    if (!vault.salt || !vault.iv || !vault.content) {
      throw new Error("Invalid vault");
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
    showToast("备份已导入，请用对应主密码解锁");
    lockVault();
  } catch (error) {
    console.error(error);
    showToast("导入失败：备份文件格式不正确");
  } finally {
    event.target.value = "";
  }
}

function createStarterRecords() {
  const now = new Date().toISOString();
  return [
    {
      id: createId(),
      title: "GitHub",
      url: "https://github.com",
      username: "admin",
      password: "Change-Me-After-Login-2026!",
      loginMethod: "password",
      category: "dev",
      note: "示例数据：用于展示字段结构，正式使用前请删除或编辑。",
      createdAt: now,
      updatedAt: now
    },
    {
      id: createId(),
      title: "Gmail",
      url: "https://mail.google.com",
      username: "example@gmail.com",
      password: "LocalVault#Example#18",
      loginMethod: "password",
      category: "personal",
      note: "支持记录账号、网址、二次验证说明和恢复码位置。",
      createdAt: now,
      updatedAt: now
    }
  ];
}

function getHost(url) {
  try {
    return url ? new URL(url).host : "";
  } catch {
    return url;
  }
}

function formatDate(value) {
  if (!value) return "未知";
  return new Intl.DateTimeFormat("zh-CN", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  }).format(new Date(value));
}

function escapeHtml(value) {
  // 所有用户输入渲染前都转义，降低备注和标题里的 XSS 风险。
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function bindEvents() {
  els.authForm.addEventListener("submit", handleAuth);
  els.newItemButton.addEventListener("click", openCreateDialog);
  els.itemForm.addEventListener("submit", saveRecord);
  els.closeDialogButton.addEventListener("click", () => els.itemDialog.close());
  els.cancelButton.addEventListener("click", () => els.itemDialog.close());
  els.deleteButton.addEventListener("click", deleteSelectedRecord);
  els.settingsButton.addEventListener("click", () => {
    els.settingsMessage.textContent = "";
    els.currentMasterPasswordInput.value = "";
    els.newMasterPasswordInput.value = "";
    els.confirmNewMasterPasswordInput.value = "";
    els.settingsDialog.showModal();
  });
  els.closeSettingsButton.addEventListener("click", () => els.settingsDialog.close());
  els.changeMasterPasswordButton.addEventListener("click", changeMasterPassword);
  els.generateButton.addEventListener("click", generatePassword);
  els.toggleFormPasswordButton.addEventListener("click", () => {
    setFormPasswordVisibility(els.passwordInput.type === "password");
  });
  els.lengthInput.addEventListener("input", () => {
    els.lengthValue.textContent = els.lengthInput.value;
  });
  els.searchInput.addEventListener("input", render);
  els.sortSelect.addEventListener("change", render);
  els.lockButton.addEventListener("click", lockVault);
  els.exportButton.addEventListener("click", exportVault);
  els.importInput.addEventListener("change", importVault);

  els.categoryList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-category]");
    if (!button) return;
    state.activeCategory = button.dataset.category;
    render();
  });

  els.vaultList.addEventListener("click", (event) => {
    const card = event.target.closest("[data-id]");
    if (!card) return;
    const now = Date.now();
    const id = card.dataset.id;
    const record = state.records.find((item) => item.id === id);
    const isQuickRepeatClick = state.lastListClick.id === id && now - state.lastListClick.time < 450;
    state.lastListClick = { id, time: now };
    if (event.detail >= 2 || isQuickRepeatClick) {
      if (record) openRecordUrl(record);
      return;
    }
    state.selectedId = id;
    render();
  });

  els.detailPanel.addEventListener("click", async (event) => {
    const action = event.target.dataset.action;
    const record = state.records.find((item) => item.id === state.selectedId);
    if (!action || !record) return;

    if (action === "edit") openEditDialog(record);
    if (action === "copy-password") await copyToClipboard(record.password, "密码已复制");
    if (action === "copy-username") await copyToClipboard(record.username, "用户名已复制");
    if (action === "copy-url") await copyToClipboard(record.url, "网址已复制");
    if (action === "toggle-password") {
      if (state.visiblePasswordIds.has(record.id)) {
        state.visiblePasswordIds.delete(record.id);
      } else {
        state.visiblePasswordIds.add(record.id);
      }
      renderDetail();
    }
  });

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      els.searchInput.focus();
    }
  });
}

async function init() {
  configureAuthScreen();
  bindEvents();
  const restored = await restoreSessionUnlock();
  if (restored) {
    return;
  }
  els.masterPasswordInput.focus();
}

init();
