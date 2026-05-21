const STORAGE_KEY = "zreo-password-vault-v1";
const SESSION_KEY = "zreo-password-session-key";
const SESSION_PASSWORD_KEY = "zreo-password-session-master";
const IDLE_LOCK_KEY = "zreo-password-idle-minutes";
const DEFAULT_CATEGORY = "未分类";
const MAX_BOOKMARK_HTML_BYTES = 20 * 1024 * 1024;
const MAX_CHROME_PASSWORD_CSV_BYTES = 10 * 1024 * 1024;

const state = {
  records: [],
  selectedId: null,
  visiblePasswordIds: new Set(),
  selectedRecordIds: new Set(),
  expandedGroups: new Set(),
  lastListClick: { id: null, time: 0 },
  activeCategory: "全部",
  contextCategoryName: "",
  isBatchDeleteMode: false,
  key: null,
  mode: "create"
};

let idleTimer = null;

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
  idleLockInput: document.querySelector("#idleLockInput"),
  idleLockValue: document.querySelector("#idleLockValue"),
  newItemButton: document.querySelector("#newItemButton"),
  batchToolbar: document.querySelector("#batchToolbar"),
  batchModeButton: document.querySelector("#batchModeButton"),
  selectVisibleButton: document.querySelector("#selectVisibleButton"),
  clearSelectedButton: document.querySelector("#clearSelectedButton"),
  deleteSelectedButton: document.querySelector("#deleteSelectedButton"),
  exitBatchButton: document.querySelector("#exitBatchButton"),
  categoryList: document.querySelector("#categoryList"),
  settingsButton: document.querySelector("#settingsButton"),
  exportButton: document.querySelector("#exportButton"),
  importInput: document.querySelector("#importInput"),
  chromePasswordInput: document.querySelector("#chromePasswordInput"),
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
  accountTagInput: document.querySelector("#accountTagInput"),
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
  categoryContextMenu: document.querySelector("#categoryContextMenu"),
  renameCategoryButton: document.querySelector("#renameCategoryButton"),
  removeCategoryButton: document.querySelector("#removeCategoryButton"),
  renameCategoryDialog: document.querySelector("#renameCategoryDialog"),
  renameCategoryForm: document.querySelector("#renameCategoryForm"),
  renameCategorySource: document.querySelector("#renameCategorySource"),
  renameCategoryInput: document.querySelector("#renameCategoryInput"),
  renameCategoryMessage: document.querySelector("#renameCategoryMessage"),
  closeRenameCategoryButton: document.querySelector("#closeRenameCategoryButton"),
  cancelRenameCategoryButton: document.querySelector("#cancelRenameCategoryButton"),
  deleteCategoryDialog: document.querySelector("#deleteCategoryDialog"),
  deleteCategoryForm: document.querySelector("#deleteCategoryForm"),
  deleteCategoryName: document.querySelector("#deleteCategoryName"),
  deleteCategoryPasswordInput: document.querySelector("#deleteCategoryPasswordInput"),
  deleteCategoryMessage: document.querySelector("#deleteCategoryMessage"),
  closeDeleteCategoryButton: document.querySelector("#closeDeleteCategoryButton"),
  cancelDeleteCategoryButton: document.querySelector("#cancelDeleteCategoryButton"),
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
    localStorage.setItem(SESSION_KEY, "unlocked");
    localStorage.setItem(SESSION_PASSWORD_KEY, password);
  }
}

async function restoreSessionUnlock() {
  const password = localStorage.getItem(SESSION_PASSWORD_KEY);
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
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_PASSWORD_KEY);
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
    phone: { label: "手机号登录", short: "手机号" },
    other: { label: "其他方式", short: "其他" }
  };
  return map[method] || map.password;
}

function getRecordLoginMethod(record) {
  return record.loginMethod || (record.password ? "password" : "other");
}

function getRecordHost(record) {
  return getHost(record.url) || "未设置网址";
}

function getRecordAccountTag(record) {
  return record.accountTag || "默认";
}

function getRecordGroupTitle(record) {
  return record.title || getRecordHost(record);
}

function getRecordIconText(record) {
  const method = getLoginMethodMeta(getRecordLoginMethod(record));
  if (method.short === "Google") return "G";
  if (method.short === "GitHub") return "GH";
  if (method.short === "Apple") return "A";
  if (method.short === "微信") return "微";
  if (method.short === "手机号") return "号";
  const title = String(getRecordGroupTitle(record) || "").trim();
  return title ? title.slice(0, 1).toUpperCase() : "〇";
}

function getRecordIconTone(record) {
  const method = getLoginMethodMeta(getRecordLoginMethod(record));
  if (method.short === "Google") return "google";
  if (method.short === "GitHub") return "github";
  if (method.short === "Apple") return "apple";
  if (method.short === "微信") return "wechat";
  if (method.short === "手机号") return "phone";
  return "default";
}

function getRecordGroupedCount(record) {
  // 同一标题和网址下可能有多个账号，详情区用这个数量提示用户别选错记录。
  return state.records.filter((item) => getRecordGroupTitle(item) === getRecordGroupTitle(record) && item.url === record.url).length;
}

function getRecordBookmarkPath(record) {
  // 书签文件把分类放在第一层文件夹，剩余层级压进标签 / 环境。
  const category = normalizeCategory(record.category);
  const extraSegments = splitBookmarkPath(record.accountTag);
  return [category, ...extraSegments].filter(Boolean);
}

function splitBookmarkPath(pathValue) {
  return String(pathValue ?? "")
    .split("/")
    .map((segment) => segment.trim())
    .filter(Boolean);
}

function joinBookmarkPath(segments) {
  return segments.filter(Boolean).join("/");
}

function normalizeBookmarkTitle(title, url) {
  const cleanedTitle = String(title ?? "").trim();
  if (cleanedTitle) {
    return cleanedTitle;
  }
  return getHost(url) || "未命名";
}

function recordImportKey(record) {
  return [
    String(record.title ?? "").trim().toLowerCase(),
    String(record.url ?? "").trim().toLowerCase(),
    normalizeCategory(record.category).toLowerCase(),
    String(record.accountTag ?? "").trim().toLowerCase()
  ].join("|");
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
        record.accountTag,
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

function groupRecordsByTitle(records) {
  const groups = new Map();
  records.forEach((record) => {
    const title = getRecordGroupTitle(record);
    if (!groups.has(title)) {
      groups.set(title, []);
    }
    groups.get(title).push(record);
  });
  return [...groups.entries()].map(([title, items]) => ({ title, items }));
}

function shouldExpandRecordGroup(group) {
  if (group.items.length <= 1) {
    return true;
  }
  return state.expandedGroups.has(group.title)
    || group.items.some((record) => record.id === state.selectedId);
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
    <button class="category-button ${category === state.activeCategory ? "is-active" : ""}" type="button" data-category="${escapeHtml(category)}" data-category-menu="${category !== "全部" ? "true" : "false"}">
      <span>${escapeHtml(category)}</span>
      <strong>${counts.get(category)}</strong>
    </button>
  `).join("");

  els.categoryOptions.innerHTML = categories
    .filter((category) => category !== "全部")
    .map((category) => `<option value="${escapeHtml(category)}"></option>`)
    .join("");
}

function getVisibleRecordIds() {
  return new Set(getFilteredRecords().map((record) => record.id));
}

function syncSelectedRecordIdsWithVisible() {
  if (!state.isBatchDeleteMode) return;
  const visibleIds = getVisibleRecordIds();
  state.selectedRecordIds = new Set(
    [...state.selectedRecordIds].filter((id) => visibleIds.has(id))
  );
}

function closeCategoryContextMenu() {
  if (!els.categoryContextMenu) return;
  els.categoryContextMenu.hidden = true;
}

function openCategoryContextMenu(categoryName, position) {
  if (!els.categoryContextMenu || categoryName === "全部") return;
  state.contextCategoryName = categoryName;
  state.activeCategory = categoryName;
  render();
  els.categoryContextMenu.hidden = false;
  const maxX = window.innerWidth - 156;
  const maxY = window.innerHeight - 96;
  els.categoryContextMenu.style.left = `${Math.max(8, Math.min(position.x, maxX))}px`;
  els.categoryContextMenu.style.top = `${Math.max(8, Math.min(position.y, maxY))}px`;
}

function renderBatchToolbar() {
  if (!els.batchToolbar || !els.batchModeButton) return;
  els.batchToolbar.hidden = !state.isBatchDeleteMode;
  els.batchModeButton.hidden = state.isBatchDeleteMode;
  if (els.deleteSelectedButton) {
    const count = state.selectedRecordIds.size;
    els.deleteSelectedButton.disabled = count === 0;
    els.deleteSelectedButton.textContent = count ? `删除选中（${count}）` : "删除选中";
  }
}

function enterBatchDeleteMode() {
  state.isBatchDeleteMode = true;
  state.selectedRecordIds.clear();
  syncSelectedRecordIdsWithVisible();
  render();
}

function exitBatchDeleteMode() {
  state.isBatchDeleteMode = false;
  state.selectedRecordIds.clear();
  render();
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
  syncSelectedRecordIdsWithVisible();
  renderBatchToolbar();
  const records = getFilteredRecords();
  if (!records.length) {
    els.vaultList.innerHTML = `<div class="empty-list">没有匹配记录。可以新建一条，或者换个关键词试试。</div>`;
    return;
  }

  els.vaultList.innerHTML = groupRecordsByTitle(records).map((group, index) => `
    <section class="record-group">
      ${renderGroupHeading(group, index)}
      ${shouldExpandRecordGroup(group) ? `
        <div class="group-records">
          ${group.items.map(renderRecordCard).join("")}
        </div>
      ` : ""}
    </section>
  `).join("");
}

function renderGroupHeading(group, index) {
  const isExpanded = shouldExpandRecordGroup(group);
  if (group.items.length <= 1) {
    return `
      <div class="group-heading">
        <strong>${escapeHtml(group.title)}</strong>
        <span>${group.items.length} 个账号</span>
      </div>
    `;
  }

  return `
    <button class="group-heading group-toggle" type="button" data-group-index="${index}">
      <strong>${escapeHtml(group.title)}</strong>
      <span>${isExpanded ? "收起" : "展开"} · ${group.items.length} 个账号</span>
    </button>
  `;
}

function renderRecordCard(record) {
  const loginMethod = getLoginMethodMeta(getRecordLoginMethod(record));
  const isChecked = state.selectedRecordIds.has(record.id);
  const metaLine = [
    record.username || "未设置账号",
    getRecordAccountTag(record),
    loginMethod.label,
    record.category,
    formatDate(record.updatedAt)
  ].filter(Boolean).join(" · ");
  return `
    <button class="vault-card ${record.id === state.selectedId ? "is-active" : ""} ${state.isBatchDeleteMode ? "is-batch-mode" : ""} ${isChecked ? "is-checked" : ""}" type="button" data-id="${record.id}" title="${state.isBatchDeleteMode ? "点击勾选记录" : "双击打开网址"}">
      ${state.isBatchDeleteMode ? `<span class="vault-card-checkbox" aria-hidden="true">${isChecked ? "✓" : ""}</span>` : ""}
      <div class="vault-card-icon tone-${escapeHtml(getRecordIconTone(record))}" aria-hidden="true">${escapeHtml(getRecordIconText(record))}</div>
      <div class="vault-card-body">
        <div class="vault-card-title">
          <strong>${escapeHtml(record.title)}</strong>
          <span class="vault-card-time">${escapeHtml(formatDate(record.updatedAt))}</span>
        </div>
        <div class="vault-meta one-line">${escapeHtml(metaLine)}</div>
      </div>
    </button>
  `;
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
  const passwordActionText = isPasswordVisible ? "🙈" : "👁";
  const sameTitleCount = getRecordGroupedCount(record);
  els.detailPanel.innerHTML = `
    <div class="detail-header">
      <div class="detail-profile">
        <div class="detail-avatar tone-${escapeHtml(getRecordIconTone(record))}" aria-hidden="true">${escapeHtml(getRecordIconText(record))}</div>
        <div class="detail-title">
          <div class="detail-title-row">
            <h3>${escapeHtml(record.title)}</h3>
            <span class="detail-title-badge">${escapeHtml(record.password ? strength.label : loginMethod.short)}</span>
          </div>
          <div class="detail-chip-row">
            <span class="detail-chip">${escapeHtml(getRecordAccountTag(record))}</span>
            <span class="detail-chip detail-chip-alt">${escapeHtml(loginMethod.label)}</span>
          </div>
        </div>
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
      ${renderField("密码", passwordText, passwordAction, true, passwordActionText, "查看或隐藏密码", "icon-button")}
      <div class="field-row">
        <span>强度</span>
        <div class="field-stack">
          <strong>${strength.label}</strong>
          <div class="strength-bar"><div class="strength-fill" style="width: ${strength.score}%"></div></div>
        </div>
      </div>
      <div class="insights-grid">
        <article class="insight-card">
          <span>最近更新</span>
          <strong>${formatDate(record.updatedAt)}</strong>
        </article>
        <article class="insight-card">
          <span>同标题账号</span>
          <strong>${sameTitleCount} 个</strong>
        </article>
      </div>
      <div class="field-row field-row-plain">
        <span>备注</span>
        <p>${escapeHtml(record.note || "无备注")}</p>
      </div>
    </div>
  `;
}

function renderField(label, value, action, isCode = false, actionText = "复制", actionLabel = actionText, buttonClass = "ghost-button") {
  const body = isCode ? `<code>${escapeHtml(value)}</code>` : `<p>${escapeHtml(value)}</p>`;
  const button = action
    ? `<button class="${buttonClass}" type="button" data-action="${action}" aria-label="${escapeHtml(actionLabel)}">${actionText}</button>`
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
    if (window.desktopBridge?.openExternal) {
      window.desktopBridge.openExternal(url.href)
        .then((result) => {
          if (!result || result.ok === false) {
            window.open(url.href, "_blank", "noopener");
          }
        })
        .catch(() => {
          window.open(url.href, "_blank", "noopener");
        });
      return;
    }
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
  closeCategoryContextMenu();
  if (state.isBatchDeleteMode) {
    exitBatchDeleteMode();
  }
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
  closeCategoryContextMenu();
  if (state.isBatchDeleteMode) {
    exitBatchDeleteMode();
  }
  state.mode = "edit";
  els.dialogTitle.textContent = "编辑记录";
  els.deleteButton.hidden = false;
  els.titleInput.value = record.title;
  els.categoryInput.value = record.category;
  els.urlInput.value = record.url || "";
  els.usernameInput.value = record.username || "";
  els.accountTagInput.value = record.accountTag || "";
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
    accountTag: els.accountTagInput.value.trim(),
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

async function validateMasterPassword(password) {
  const storedVault = getStoredVault();
  if (!storedVault) {
    throw new Error("Vault not found");
  }
  const key = await deriveKey(password, base64ToBytes(storedVault.salt));
  await decryptVault(storedVault, key);
}

function openRenameCategoryDialog() {
  closeCategoryContextMenu();
  if (!state.contextCategoryName) return;
  els.renameCategoryMessage.textContent = "";
  els.renameCategorySource.textContent = state.contextCategoryName;
  els.renameCategoryInput.value = state.contextCategoryName;
  els.renameCategoryDialog.showModal();
  els.renameCategoryInput.focus();
  els.renameCategoryInput.select();
}

async function saveCategoryRename(event) {
  event.preventDefault();
  const oldName = state.contextCategoryName;
  const nextName = normalizeCategory(els.renameCategoryInput.value);
  els.renameCategoryMessage.textContent = "";

  if (!oldName) return;
  if (!nextName) {
    els.renameCategoryMessage.textContent = "分类名不能为空。";
    return;
  }
  if (nextName === oldName) {
    els.renameCategoryDialog.close();
    return;
  }

  state.records = state.records.map((record) => (
    record.category === oldName
      ? { ...record, category: nextName, updatedAt: new Date().toISOString() }
      : record
  ));

  if (state.activeCategory === oldName) {
    state.activeCategory = nextName;
  }

  await persistRecords();
  els.renameCategoryDialog.close();
  render();
  showToast("分类已更新");
}

function openDeleteCategoryDialog() {
  closeCategoryContextMenu();
  if (!state.contextCategoryName) return;
  els.deleteCategoryMessage.textContent = "";
  els.deleteCategoryName.textContent = state.contextCategoryName;
  els.deleteCategoryPasswordInput.value = "";
  els.deleteCategoryDialog.showModal();
  els.deleteCategoryPasswordInput.focus();
}

async function deleteCategoryRecords(event) {
  event.preventDefault();
  const categoryName = state.contextCategoryName;
  const password = els.deleteCategoryPasswordInput.value;
  els.deleteCategoryMessage.textContent = "";

  if (!categoryName || categoryName === "全部") return;
  if (!password) {
    els.deleteCategoryMessage.textContent = "请输入主密码。";
    return;
  }

  try {
    await validateMasterPassword(password);
    state.records = state.records.filter((record) => record.category !== categoryName);
    if (state.activeCategory === categoryName) {
      state.activeCategory = "全部";
    }
    if (!state.records.some((record) => record.id === state.selectedId)) {
      state.selectedId = state.records[0] ? state.records[0].id : null;
    }
    await persistRecords();
    els.deleteCategoryDialog.close();
    render();
    showToast("分类及其记录已删除");
  } catch (error) {
    console.error(error);
    els.deleteCategoryMessage.textContent = "主密码错误。";
  }
}

async function deleteSelectedRecords() {
  syncSelectedRecordIdsWithVisible();
  const ids = [...state.selectedRecordIds];
  if (!ids.length) {
    showToast("请先选择要删除的记录");
    return;
  }

  const confirmed = window.confirm(`确认删除选中的 ${ids.length} 条记录？此操作会写入新的本地加密库。`);
  if (!confirmed) return;

  state.records = state.records.filter((record) => !state.selectedRecordIds.has(record.id));
  state.selectedRecordIds.clear();
  state.isBatchDeleteMode = false;
  if (!state.records.some((record) => record.id === state.selectedId)) {
    state.selectedId = state.records[0] ? state.records[0].id : null;
  }
  await persistRecords();
  render();
  showToast("选中记录已删除");
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
    localStorage.setItem(SESSION_KEY, "unlocked");
    localStorage.setItem(SESSION_PASSWORD_KEY, newPassword);
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
  const storedVault = getStoredVault();

  try {
    if (!storedVault) {
      if (password.length < 8) {
        els.authMessage.textContent = "主密码至少 8 位。";
        return;
      }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      state.key = await deriveKey(password, salt);
      state.records = createStarterRecords();
      state.selectedId = state.records[0].id;
      const vault = await encryptVault(state.records, state.key, salt);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
      localStorage.setItem(SESSION_PASSWORD_KEY, password);
    } else {
      await unlockWithPassword(password, { rememberSession: true });
    }

    localStorage.setItem(SESSION_KEY, "unlocked");
    els.authScreen.classList.add("is-hidden");
    els.masterPasswordInput.value = "";
    render();
    startIdleTimer();
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
    ? "输入主密码解锁。也可在设置中开启自动锁定。"
    : "主密码用于派生本地加密密钥。它不会上传，也无法找回，请认真记住。";
  els.authSubmitButton.textContent = hasVault ? "解锁进入" : "创建并进入";
  // 单密码输入，不再需要确认密码
  if (els.confirmPasswordLabel) els.confirmPasswordLabel.style.display = "none";
  if (els.confirmPasswordInput) els.confirmPasswordInput.required = false;
}

function stopIdleTimer() {
  if (idleTimer !== null) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
}

function startIdleTimer() {
  stopIdleTimer();
  const minutes = parseInt(localStorage.getItem(IDLE_LOCK_KEY), 10) || 5;
  if (minutes <= 0) return;
  idleTimer = setTimeout(() => {
    if (state.key) {
      lockVault();
      showToast("已自动锁定");
    }
  }, minutes * 60 * 1000);
}

function resetIdleTimer() {
  if (idleTimer !== null && state.key) {
    startIdleTimer();
  }
}

function lockVault() {
  stopIdleTimer();
  state.key = null;
  state.records = [];
  state.selectedId = null;
  state.visiblePasswordIds.clear();
  state.selectedRecordIds.clear();
  state.isBatchDeleteMode = false;
  state.contextCategoryName = "";
  localStorage.removeItem(SESSION_KEY);
  localStorage.removeItem(SESSION_PASSWORD_KEY);
  closeCategoryContextMenu();
  configureAuthScreen();
  els.authScreen.classList.remove("is-hidden");
  els.masterPasswordInput.focus();
}

function openSettingsDialog() {
  closeCategoryContextMenu();
  els.settingsMessage.textContent = "";
  els.currentMasterPasswordInput.value = "";
  els.newMasterPasswordInput.value = "";
  els.confirmNewMasterPasswordInput.value = "";
  els.settingsDialog.showModal();
}

async function exportBookmarksHtml() {
  try {
    const exportableRecords = state.records.filter((record) => String(record.url ?? "").trim());
    if (!exportableRecords.length) {
      showToast("还没有可导出的书签网址");
      return;
    }

    const html = buildBookmarkHtml(exportableRecords);
    const fileName = `zreo-bookmarks-${new Date().toISOString().slice(0, 10)}.html`;
    if (window.desktopBridge?.saveTextFile) {
      const result = await window.desktopBridge.saveTextFile({
        title: "导出书签 HTML",
        defaultPath: fileName,
        mimeType: "text/html",
        content: html
      });
      if (!result || result.canceled) {
        return;
      }
      showToast(`已导出 ${exportableRecords.length} 条书签`);
      return;
    }

    const blob = new Blob([html], { type: "text/html;charset=UTF-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
    showToast(`已导出 ${exportableRecords.length} 条书签`);
  } catch (error) {
    console.error(error);
    showToast("导出失败：请检查桌面端保存权限");
  }
}

async function importBookmarksText(text) {
  try {
    const trimmed = String(text ?? "").trim();

    if (!trimmed) {
      throw new Error("No bookmarks found");
    }

    if (trimmed.startsWith("{")) {
      const vault = JSON.parse(trimmed);
      if (!vault.salt || !vault.iv || !vault.content) {
        throw new Error("Invalid vault");
      }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
      showToast("旧版加密备份已导入，请用对应主密码解锁");
      lockVault();
      return true;
    }

    const importedRecords = parseBookmarkHtml(text);
    if (!importedRecords.length) {
      throw new Error("No bookmarks found");
    }

    const now = new Date().toISOString();
    const existingRecords = [...state.records];
    const existingByKey = new Map(existingRecords.map((record) => [recordImportKey(record), record]));
    const stagedByKey = new Map();
    const appendedRecords = [];

    importedRecords.forEach((item) => {
      const record = createRecordFromBookmarkItem(item, now);
      const key = recordImportKey(record);
      const current = existingByKey.get(key) || stagedByKey.get(key);
      if (current) {
        // 同标题 + 同网址 + 同标签则合并到已有记录，密码继续保留在本地库。
        current.title = record.title;
        current.url = record.url;
        current.category = record.category;
        current.accountTag = record.accountTag;
        current.updatedAt = now;
        return;
      }

      stagedByKey.set(key, record);
      appendedRecords.push(record);
    });

    state.records = appendedRecords.length ? [...existingRecords, ...appendedRecords] : existingRecords;

    await persistRecords();
    if (appendedRecords.length) {
      state.selectedId = appendedRecords[0].id;
    } else if (!state.records.some((record) => record.id === state.selectedId)) {
      state.selectedId = state.records[0] ? state.records[0].id : null;
    }
    render();
    showToast(`已导入 ${importedRecords.length} 条书签`);
    return true;
  } catch (error) {
    console.error(error);
    if (error && error.message === "File too large") {
      showToast("导入失败：书签文件太大了");
    } else if (error && error.message === "No bookmarks found") {
      showToast("导入失败：没有识别到书签内容");
    } else if (error && error.message === "Invalid vault") {
      showToast("导入失败：旧版加密备份格式不正确");
    } else {
      showToast("导入失败：请确认是 Google/Chrome 导出的书签 HTML");
    }
    return false;
  }
}

async function importBookmarksHtml(event) {
  const file = event.target.files[0];
  if (!file) return;

  try {
    if (file.size > MAX_BOOKMARK_HTML_BYTES) {
      throw new Error("File too large");
    }

    const text = await file.text();
    await importBookmarksText(text);
  } catch (error) {
    console.error(error);
    if (error && error.message === "File too large") {
      showToast("导入失败：书签文件太大了");
    } else {
      showToast("导入失败：请确认是 Google/Chrome 导出的书签 HTML");
    }
  } finally {
    event.target.value = "";
  }
}

async function importChromePasswordsCsv(event) {
  const file = event.target.files[0];
  if (!file) return;

  try {
    if (file.size > MAX_CHROME_PASSWORD_CSV_BYTES) {
      throw new Error("File too large");
    }

    const text = await file.text();
    const result = await importChromePasswordsText(text);
    if (result.updated > 0 || result.created > 0) {
      showToast(`已更新 ${result.updated} 条，新增 ${result.created} 条，跳过 ${result.skipped} 条`);
    } else {
      showToast("没有匹配到现有域名，未导入任何密码");
    }
  } catch (error) {
    console.error(error);
    if (error && error.message === "File too large") {
      showToast("导入失败：Chrome 密码 CSV 文件太大了");
    } else if (error && error.message === "No passwords found") {
      showToast("导入失败：没有识别到 Chrome 密码内容");
    } else {
      showToast("导入失败：请确认是 Chrome 导出的密码 CSV");
    }
  } finally {
    event.target.value = "";
  }
}

async function importChromePasswordsText(text) {
  const items = parseChromePasswordCsv(text);
  if (!items.length) {
    throw new Error("No passwords found");
  }

  const now = new Date().toISOString();
  const indexes = buildUrlRecordIndexes(state.records);
  let updated = 0;
  let created = 0;
  let skipped = 0;

  items.forEach((item) => {
    const result = applyChromePasswordItem(item, indexes, now);
    if (result === "updated") {
      updated += 1;
    } else if (result === "created") {
      created += 1;
    } else {
      skipped += 1;
    }
  });

  if (updated > 0 || created > 0) {
    await persistRecords();
    render();
  }

  return { updated, created, skipped };
}

function parseChromePasswordCsv(text) {
  const rows = parseCsvRows(String(text ?? "").replace(/^\uFEFF/, ""));
  if (!rows.length) {
    throw new Error("No passwords found");
  }

  const header = rows[0].map((cell) => cell.trim().toLowerCase());
  const requiredFields = ["name", "url", "username", "password", "note"];
  const fieldIndexes = requiredFields.reduce((result, fieldName) => {
    const index = header.indexOf(fieldName);
    if (index === -1) {
      throw new Error("Invalid CSV");
    }
    result[fieldName] = index;
    return result;
  }, {});

  return rows.slice(1)
    .map((row) => ({
      name: (row[fieldIndexes.name] || "").trim(),
      url: (row[fieldIndexes.url] || "").trim(),
      username: (row[fieldIndexes.username] || "").trim(),
      password: row[fieldIndexes.password] || "",
      note: (row[fieldIndexes.note] || "").trim()
    }))
    .filter((item) => item.url && (item.username || item.password || item.note));
}

function parseCsvRows(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let inQuotes = false;

  // 状态机解析 CSV，避免密码或备注里的逗号、引号、换行被错误拆开。
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const nextChar = text[index + 1];

    if (inQuotes) {
      if (char === "\"" && nextChar === "\"") {
        cell += "\"";
        index += 1;
      } else if (char === "\"") {
        inQuotes = false;
      } else {
        cell += char;
      }
      continue;
    }

    if (char === "\"") {
      inQuotes = true;
    } else if (char === ",") {
      row.push(cell);
      cell = "";
    } else if (char === "\n" || char === "\r") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      if (char === "\r" && nextChar === "\n") {
        index += 1;
      }
    } else {
      cell += char;
    }
  }

  if (inQuotes) {
    throw new Error("Invalid CSV");
  }

  if (cell || row.length) {
    row.push(cell);
    rows.push(row);
  }

  return rows.filter((cells) => cells.some((cellValue) => String(cellValue).trim()));
}

function buildUrlRecordIndexes(records) {
  const exact = new Map();
  const path = new Map();
  const host = new Map();

  records.forEach((record) => {
    const keys = getUrlMatchKeys(record.url);
    if (keys.exact) {
      addRecordToUrlIndex(exact, keys.exact, record);
    }
    if (keys.path) {
      addRecordToUrlIndex(path, keys.path, record);
    }
    if (keys.host) {
      addRecordToUrlIndex(host, keys.host, record);
    }
  });

  return { exact, path, host };
}

function addRecordToUrlIndex(index, key, record) {
  if (!index.has(key)) {
    index.set(key, []);
  }
  index.get(key).push(record);
}

function applyChromePasswordItem(item, indexes, now) {
  const keys = getUrlMatchKeys(item.url);
  const domainRecords = indexes.host.get(keys.host) || [];
  if (!keys.host || !domainRecords.length) {
    return "skipped";
  }

  const target = findChromePasswordTarget(item, indexes, domainRecords);
  if (target) {
    updateRecordFromChromePassword(target, item, now);
    return "updated";
  }

  const baseRecord = findChromePasswordBaseRecord(item, indexes, domainRecords);
  if (!baseRecord) {
    return "skipped";
  }

  const record = createRecordFromChromePasswordItem(item, baseRecord, now);
  state.records.push(record);
  addChromePasswordRecordToIndexes(record, indexes);
  return "created";
}

function findChromePasswordTarget(item, indexes, domainRecords) {
  const keys = getUrlMatchKeys(item.url);
  const candidates = [];
  const seenIds = new Set();

  // 先完整网址匹配，再用路径和域名兜底；同域名允许多账号导入。
  [indexes.exact.get(keys.exact), indexes.path.get(keys.path), domainRecords].forEach((records) => {
    (records || []).forEach((record) => {
      if (!seenIds.has(record.id)) {
        seenIds.add(record.id);
        candidates.push(record);
      }
    });
  });

  if (!candidates.length) {
    return null;
  }

  const username = item.username.trim().toLowerCase();
  if (username) {
    const sameUsername = candidates.filter((record) => normalizeChromeUsername(record.username) === username);
    if (sameUsername.length === 1) {
      return sameUsername[0];
    }
    if (sameUsername.length > 1) {
      return null;
    }

    const blankUsername = candidates.filter((record) => !normalizeChromeUsername(record.username));
    if (blankUsername.length === 1) {
      return blankUsername[0];
    }

    return null;
  }

  return candidates.length === 1 ? candidates[0] : null;
}

function findChromePasswordBaseRecord(item, indexes, domainRecords) {
  const keys = getUrlMatchKeys(item.url);
  const pathRecords = indexes.path.get(keys.path) || [];
  const exactRecords = indexes.exact.get(keys.exact) || [];
  return exactRecords[0] || pathRecords[0] || domainRecords[0] || null;
}

function updateRecordFromChromePassword(record, item, now) {
  record.username = item.username;
  record.password = item.password;
  record.note = item.note;
  record.loginMethod = "password";
  record.updatedAt = now;
}

function createRecordFromChromePasswordItem(item, baseRecord, now) {
  return {
    id: createId(),
    title: baseRecord.title || normalizeBookmarkTitle(item.name, item.url),
    url: item.url,
    username: item.username,
    accountTag: baseRecord.accountTag || "",
    loginMethod: "password",
    category: normalizeCategory(baseRecord.category),
    password: item.password,
    note: item.note,
    createdAt: now,
    updatedAt: now
  };
}

function addChromePasswordRecordToIndexes(record, indexes) {
  const keys = getUrlMatchKeys(record.url);
  if (keys.exact) {
    addRecordToUrlIndex(indexes.exact, keys.exact, record);
  }
  if (keys.path) {
    addRecordToUrlIndex(indexes.path, keys.path, record);
  }
  if (keys.host) {
    addRecordToUrlIndex(indexes.host, keys.host, record);
  }
}

function normalizeChromeUsername(value) {
  return String(value ?? "").trim().toLowerCase();
}

function getUrlMatchKeys(value) {
  const cleaned = String(value ?? "").trim();
  if (!cleaned) {
    return { exact: "", path: "", host: "" };
  }

  try {
    const parsed = new URL(cleaned);
    parsed.hash = "";
    return {
      exact: parsed.href.toLowerCase(),
      path: `${parsed.origin}${parsed.pathname}`.toLowerCase(),
      host: parsed.hostname.toLowerCase()
    };
  } catch (error) {
    const withoutHash = cleaned.split("#")[0].trim().toLowerCase();
    return {
      exact: withoutHash,
      path: withoutHash.split("?")[0],
      host: ""
    };
  }
}

async function importBookmarksFromDesktop() {
  if (!window.desktopBridge?.pickFile || !window.desktopBridge?.readTextFile) {
    els.importInput.click();
    return;
  }

  try {
    const result = await window.desktopBridge.pickFile({
      title: "导入书签 HTML",
      filters: [
        { name: "HTML", extensions: ["html", "htm"] },
        { name: "JSON", extensions: ["json"] },
        { name: "All Files", extensions: ["*"] }
      ]
    });
    if (!result || result.canceled || !result.filePaths?.length) {
      return;
    }

    const fileResult = await window.desktopBridge.readTextFile({
      filePath: result.filePaths[0],
      maxBytes: MAX_BOOKMARK_HTML_BYTES
    });
    if (!fileResult || fileResult.canceled || typeof fileResult.content !== "string") {
      if (fileResult && fileResult.tooLarge) {
        showToast("导入失败：书签文件太大了");
      }
      return;
    }

    await importBookmarksText(fileResult.content);
  } catch (error) {
    console.error(error);
    showToast("导入失败：无法读取所选文件");
  }
}

function buildBookmarkHtml(records) {
  const now = Math.floor(Date.now() / 1000);
  const tree = buildBookmarkTree(records);
  const body = serializeBookmarkTree(tree, 1, now);
  return [
    "<!DOCTYPE NETSCAPE-Bookmark-file-1>",
    "<!-- This file was generated by 小〇密码 -->",
    '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">',
    "<TITLE>Bookmarks</TITLE>",
    "<H1>Bookmarks</H1>",
    "<DL><p>",
    body,
    "</DL><p>"
  ].join("\n");
}

function buildBookmarkTree(records) {
  // 以文件夹树组织导出内容，便于 Chrome / Google 直接识别。
  const root = {
    folders: new Map(),
    bookmarks: []
  };

  records.forEach((record) => {
    const pathSegments = getRecordBookmarkPath(record);
    let current = root;
    pathSegments.forEach((segment) => {
      if (!current.folders.has(segment)) {
        current.folders.set(segment, { folders: new Map(), bookmarks: [] });
      }
      current = current.folders.get(segment);
    });
    current.bookmarks.push(record);
  });

  return root;
}

function serializeBookmarkTree(node, depth, timestamp) {
  const indent = "  ".repeat(depth);
  const lines = [];

  for (const [folderName, child] of node.folders.entries()) {
    lines.push(`${indent}<DT><H3 ADD_DATE="${timestamp}" LAST_MODIFIED="${timestamp}">${escapeHtml(folderName)}</H3>`);
    lines.push(`${indent}<DL><p>`);
    lines.push(serializeBookmarkTree(child, depth + 1, timestamp));
    lines.push(`${indent}</DL><p>`);
  }

  for (const record of node.bookmarks) {
    if (!record.url) continue;
    const title = normalizeBookmarkTitle(record.title, record.url);
    lines.push(`${indent}<DT><A HREF="${escapeHtml(record.url)}" ADD_DATE="${timestamp}" LAST_MODIFIED="${timestamp}">${escapeHtml(title)}</A>`);
  }

  return lines.join("\n");
}

function parseBookmarkHtml(text) {
  // 按 Netscape Bookmark HTML 递归解析文件夹和链接。
  const doc = new DOMParser().parseFromString(text, "text/html");
  if (!doc || doc.querySelector("parsererror")) {
    throw new Error("Invalid bookmark HTML");
  }

  const rootDl = doc.querySelector("dl");
  if (!rootDl) {
    throw new Error("Invalid bookmark HTML");
  }

  const items = [];
  walkBookmarkDl(rootDl, [], items);
  return items;
}

function walkBookmarkDl(dlElement, folderSegments, items) {
  const dtNodes = Array.from(dlElement.children).filter((node) => node.tagName === "DT");

  dtNodes.forEach((dtNode) => {
    const directChildren = Array.from(dtNode.children);
    const folderNode = directChildren.find((node) => node.tagName === "H3" || node.tagName === "H4");
    const linkNode = directChildren.find((node) => node.tagName === "A");
    const nestedDlNode = directChildren.find((node) => node.tagName === "DL");

    if (folderNode) {
      const isToolbar = folderNode.getAttribute && folderNode.getAttribute("PERSONAL_TOOLBAR_FOLDER") === "true";
      let nextSegments;
      if (isToolbar) {
        // 跳过 Google Chrome 的"书签栏"，子文件夹直升为路径根
        nextSegments = folderSegments;
      } else {
        const folderName = folderNode.textContent.trim();
        nextSegments = folderName ? [...folderSegments, folderName] : folderSegments;
      }
      if (nestedDlNode) {
        walkBookmarkDl(nestedDlNode, nextSegments, items);
      }
      return;
    }

    if (!linkNode) {
      return;
    }

    const url = (linkNode.getAttribute("href") || "").trim();
    if (!url) {
      return;
    }

    items.push({
      title: normalizeBookmarkTitle(linkNode.textContent, url),
      url,
      folderPath: folderSegments.slice()
    });
  });
}

function createRecordFromBookmarkItem(item, now) {
  const folderPath = Array.isArray(item.folderPath) ? item.folderPath.filter(Boolean) : [];
  const category = normalizeCategory(folderPath[0] || DEFAULT_CATEGORY);
  const accountTag = joinBookmarkPath(folderPath.slice(1));
  return {
    id: createId(),
    title: normalizeBookmarkTitle(item.title, item.url),
    url: item.url,
    username: "",
    accountTag,
    loginMethod: "other",
    category,
    password: "",
    note: "",
    createdAt: now,
    updatedAt: now
  };
}

function createStarterRecords() {
  const now = new Date().toISOString();
  return [
    {
      id: createId(),
      title: "GitHub",
      url: "https://github.com",
      username: "admin",
      accountTag: "公司",
      password: "Change-Me-After-Login-2026!",
      loginMethod: "password",
      category: "开发工具",
      note: "示例数据：用于展示字段结构，正式使用前请删除或编辑。",
      createdAt: now,
      updatedAt: now
    },
    {
      id: createId(),
      title: "Gmail",
      url: "https://mail.google.com",
      username: "example@gmail.com",
      accountTag: "个人",
      password: "LocalVault#Example#18",
      loginMethod: "password",
      category: "个人账号",
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
  els.batchModeButton.addEventListener("click", enterBatchDeleteMode);
  els.selectVisibleButton.addEventListener("click", () => {
    state.selectedRecordIds = getVisibleRecordIds();
    renderList();
  });
  els.clearSelectedButton.addEventListener("click", () => {
    state.selectedRecordIds.clear();
    renderList();
  });
  els.deleteSelectedButton.addEventListener("click", deleteSelectedRecords);
  els.exitBatchButton.addEventListener("click", exitBatchDeleteMode);
  els.itemForm.addEventListener("submit", saveRecord);
  els.closeDialogButton.addEventListener("click", () => els.itemDialog.close());
  els.cancelButton.addEventListener("click", () => els.itemDialog.close());
  els.deleteButton.addEventListener("click", deleteSelectedRecord);
  els.settingsButton.addEventListener("click", openSettingsDialog);
  els.closeSettingsButton.addEventListener("click", () => els.settingsDialog.close());
  els.changeMasterPasswordButton.addEventListener("click", changeMasterPassword);
  els.generateButton.addEventListener("click", generatePassword);
  els.toggleFormPasswordButton.addEventListener("click", () => {
    setFormPasswordVisibility(els.passwordInput.type === "password");
  });
  els.loginMethodInput.addEventListener("change", () => {
    if (els.loginMethodInput.value === "phone" && !els.noteInput.value.trim()) {
      els.noteInput.value = "手机号：";
      els.noteInput.focus();
    }
  });
  els.lengthInput.addEventListener("input", () => {
    els.lengthValue.textContent = els.lengthInput.value;
  });
  if (els.idleLockInput) {
    els.idleLockInput.addEventListener("input", () => {
      const val = els.idleLockInput.value;
      if (els.idleLockValue) els.idleLockValue.textContent = val;
      localStorage.setItem(IDLE_LOCK_KEY, val);
      if (state.key) startIdleTimer();
    });
    // restore saved value
    const saved = localStorage.getItem(IDLE_LOCK_KEY);
    if (saved !== null) {
      els.idleLockInput.value = saved;
      if (els.idleLockValue) els.idleLockValue.textContent = saved;
    }
  }
  els.searchInput.addEventListener("input", render);
  els.sortSelect.addEventListener("change", render);
  els.lockButton.addEventListener("click", lockVault);
  els.exportButton.addEventListener("click", exportBookmarksHtml);
  els.importInput.addEventListener("change", importBookmarksHtml);
  els.chromePasswordInput.addEventListener("change", importChromePasswordsCsv);
  els.renameCategoryButton.addEventListener("click", openRenameCategoryDialog);
  els.removeCategoryButton.addEventListener("click", openDeleteCategoryDialog);
  els.renameCategoryForm.addEventListener("submit", saveCategoryRename);
  els.deleteCategoryForm.addEventListener("submit", deleteCategoryRecords);
  els.closeRenameCategoryButton.addEventListener("click", () => els.renameCategoryDialog.close());
  els.cancelRenameCategoryButton.addEventListener("click", () => els.renameCategoryDialog.close());
  els.closeDeleteCategoryButton.addEventListener("click", () => els.deleteCategoryDialog.close());
  els.cancelDeleteCategoryButton.addEventListener("click", () => els.deleteCategoryDialog.close());

  if (window.desktopBridge?.onAction) {
    const detachDesktopActionListener = window.desktopBridge.onAction((action) => {
      if (action === "open-settings") {
        openSettingsDialog();
      } else if (action === "export-bookmarks") {
        exportBookmarksHtml();
      } else if (action === "import-bookmarks") {
        importBookmarksFromDesktop();
      } else if (action === "lock-vault") {
        lockVault();
      } else if (action === "new-record") {
        openCreateDialog();
      }
    });

    window.addEventListener("beforeunload", () => {
      if (typeof detachDesktopActionListener === "function") {
        detachDesktopActionListener();
      }
    });
  }

  els.categoryList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-category]");
    if (!button) return;
    closeCategoryContextMenu();
    state.activeCategory = button.dataset.category;
    if (state.isBatchDeleteMode) {
      syncSelectedRecordIdsWithVisible();
    }
    render();
  });

  els.categoryList.addEventListener("contextmenu", (event) => {
    const button = event.target.closest("[data-category]");
    if (!button) return;
    const categoryName = button.dataset.category;
    if (categoryName === "全部") {
      closeCategoryContextMenu();
      return;
    }
    event.preventDefault();
    openCategoryContextMenu(categoryName, { x: event.clientX, y: event.clientY });
  });

  els.vaultList.addEventListener("click", (event) => {
    const groupToggle = event.target.closest("[data-group-index]");
    if (groupToggle) {
      const records = getFilteredRecords();
      const group = groupRecordsByTitle(records)[Number(groupToggle.dataset.groupIndex)];
      if (!group) return;
      const title = group.title;
      if (state.expandedGroups.has(title)) {
        state.expandedGroups.delete(title);
      } else {
        state.expandedGroups.add(title);
      }
      renderList();
      return;
    }

    const card = event.target.closest("[data-id]");
    if (!card) return;
    if (state.isBatchDeleteMode) {
      const id = card.dataset.id;
      if (state.selectedRecordIds.has(id)) {
        state.selectedRecordIds.delete(id);
      } else {
        state.selectedRecordIds.add(id);
      }
      renderList();
      return;
    }
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
      return;
    }
    if (event.key === "Escape") {
      closeCategoryContextMenu();
    }
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest("#categoryContextMenu") && !event.target.closest("[data-category]")) {
      closeCategoryContextMenu();
    }
  });

  els.vaultList.addEventListener("scroll", closeCategoryContextMenu);
  window.addEventListener("scroll", closeCategoryContextMenu);
  window.addEventListener("resize", closeCategoryContextMenu);
}

function setupActivityListeners() {
  const events = ["click", "keydown", "mousemove", "scroll", "focus"];
  events.forEach((ev) => {
    document.addEventListener(ev, resetIdleTimer, { passive: true });
  });
}

async function init() {
  configureAuthScreen();
  bindEvents();
  setupActivityListeners();
  const restored = await restoreSessionUnlock();
  if (restored) {
    startIdleTimer();
    return;
  }
  els.masterPasswordInput.focus();
}

init();
