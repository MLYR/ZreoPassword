const { app, BrowserWindow, Menu, dialog, shell, ipcMain } = require("electron");
const path = require("path");
const fs = require("fs/promises");
const vaultStore = require("./vault-store.cjs");
const driveSync = require("./drive-sync.cjs");

const isDev = Boolean(process.env.ELECTRON_START_URL);

let mainWindow = null;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1180,
    minHeight: 760,
    backgroundColor: "#f5f7f2",
    title: "小〇密码",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  if (isDev) {
    mainWindow.loadURL(process.env.ELECTRON_START_URL);
    mainWindow.webContents.openDevTools({ mode: "detach" });
  } else {
    mainWindow.loadFile(path.join(__dirname, "..", "index.html"));
  }

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) {
      shell.openExternal(url);
      return { action: "deny" };
    }
    return { action: "deny" };
  });

  mainWindow.webContents.on("will-navigate", (event, url) => {
    if (!/^file:\/\//i.test(url) && !/^https?:\/\//i.test(url)) {
      event.preventDefault();
      return;
    }
    if (/^https?:\/\//i.test(url)) {
      event.preventDefault();
      shell.openExternal(url);
    }
  });

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

function registerMenu() {
  const template = [
    {
      label: "文件",
      submenu: [
        {
          label: "新建记录",
          accelerator: "CmdOrCtrl+N",
          click: () => sendAction("new-record")
        },
        {
          label: "导入书签 HTML",
          accelerator: "CmdOrCtrl+O",
          click: () => sendAction("import-bookmarks")
        },
        {
          label: "导出书签 HTML",
          accelerator: "CmdOrCtrl+Shift+S",
          click: () => sendAction("export-bookmarks")
        },
        { type: "separator" },
        {
          label: "设置",
          accelerator: "CmdOrCtrl+,",
          click: () => sendAction("open-settings")
        },
        {
          label: "锁定密码库",
          accelerator: "CmdOrCtrl+L",
          click: () => sendAction("lock-vault")
        },
        { type: "separator" },
        {
          role: "quit"
        }
      ]
    },
    {
      label: "编辑",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" }
      ]
    },
    {
      label: "查看",
      submenu: [
        { role: "reload" },
        { role: "forceReload" },
        { role: "toggleDevTools" },
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" }
      ]
    }
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function sendAction(action) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send("desktop:action", action);
  }
}

function mimeToFilter(mimeType) {
  if (mimeType === "text/html") {
    return [{ name: "HTML", extensions: ["html", "htm"] }];
  }
  if (mimeType === "application/json") {
    return [{ name: "JSON", extensions: ["json"] }];
  }
  return [{ name: "All Files", extensions: ["*"] }];
}

function resolveSaveOptions(options = {}) {
  return {
    defaultPath: options.defaultPath || "export.html",
    title: options.title || "保存文件",
    filters: mimeToFilter(options.mimeType)
  };
}

function resolveOpenOptions(options = {}) {
  return {
    title: options.title || "选择文件",
    properties: ["openFile"],
    filters: options.filters || [
      { name: "HTML", extensions: ["html", "htm"] },
      { name: "JSON", extensions: ["json"] },
      { name: "CSV", extensions: ["csv"] },
      { name: "All Files", extensions: ["*"] }
    ]
  };
}

async function readLimitedTextFile(filePath, maxBytes) {
  if (typeof filePath !== "string" || !filePath.trim()) {
    return { canceled: true };
  }
  const stat = await fs.stat(filePath);
  if (typeof maxBytes === "number" && maxBytes > 0 && stat.size > maxBytes) {
    return { canceled: false, tooLarge: true, filePath, size: stat.size };
  }
  const content = await fs.readFile(filePath, "utf8");
  return { canceled: false, filePath, content, size: stat.size };
}

app.whenReady().then(() => {
  registerMenu();

  ipcMain.handle("desktop:openExternal", async (_event, url) => {
    if (typeof url !== "string" || !/^https?:\/\//i.test(url)) {
      return { ok: false, reason: "invalid-url" };
    }
    await shell.openExternal(url);
    return { ok: true };
  });

  ipcMain.handle("desktop:saveTextFile", async (_event, options = {}) => {
    const saveOptions = resolveSaveOptions(options);
    const result = await dialog.showSaveDialog(mainWindow, saveOptions);
    if (result.canceled || !result.filePath) {
      return { canceled: true };
    }
    await fs.writeFile(result.filePath, options.content ?? "", "utf8");
    return { canceled: false, filePath: result.filePath };
  });

  ipcMain.handle("desktop:readTextFile", async (_event, options = {}) => {
    const filePath = options.filePath || options.path;
    return readLimitedTextFile(filePath, options.maxBytes);
  });

  ipcMain.handle("desktop:pickFile", async (_event, options = {}) => {
    const result = await dialog.showOpenDialog(mainWindow, resolveOpenOptions(options));
    if (result.canceled || !result.filePaths.length) {
      return { canceled: true };
    }
    return { canceled: false, filePaths: result.filePaths };
  });

  ipcMain.handle("desktop:pickAndReadTextFile", async (_event, options = {}) => {
    const result = await dialog.showOpenDialog(mainWindow, resolveOpenOptions(options));
    if (result.canceled || !result.filePaths.length) {
      return { canceled: true };
    }
    // 文件选择和读取都在主进程完成，renderer 不再传任意路径要求读取。
    return readLimitedTextFile(result.filePaths[0], options.maxBytes);
  });

  ipcMain.handle("vault:getMeta", async () => vaultStore.getMeta(app));
  ipcMain.handle("vault:initialize", async (_event, meta = {}) => vaultStore.initializeVault(app, meta));
  ipcMain.handle("vault:updateMeta", async (_event, meta = {}) => vaultStore.updateMeta(app, meta));
  ipcMain.handle("vault:hasRecords", async () => vaultStore.hasRecords(app));
  ipcMain.handle("vault:listRecords", async () => vaultStore.listRecords(app));
  ipcMain.handle("vault:replaceAllRecords", async (_event, records = []) => vaultStore.replaceAllRecords(app, records));
  ipcMain.handle("vault:replaceAllRecordsWithMeta", async (_event, records = [], meta = {}) => (
    vaultStore.replaceAllRecordsWithMeta(app, records, meta)
  ));
  ipcMain.handle("vault:upsertRecords", async (_event, records = []) => vaultStore.upsertRecords(app, records));
  ipcMain.handle("vault:deleteRecords", async (_event, ids = []) => vaultStore.deleteRecords(app, ids));
  ipcMain.handle("vault:getSetting", async (_event, key) => vaultStore.getSetting(app, key));
  ipcMain.handle("vault:setSetting", async (_event, key, value) => vaultStore.setSetting(app, key, value));
  ipcMain.handle("drive:getStatus", async () => driveSync.getStatus(app));
  ipcMain.handle("drive:connect", async () => driveSync.connect(app, shell));
  ipcMain.handle("drive:disconnect", async () => driveSync.disconnect(app));
  ipcMain.handle("drive:deleteBackup", async (_event, fileId) => driveSync.deleteBackup(app, String(fileId || "")));
  ipcMain.handle("drive:getRemoteState", async () => driveSync.getRemoteState(app));
  ipcMain.handle("drive:listBackups", async () => driveSync.listBackups(app));
  ipcMain.handle("drive:markDownloaded", async (_event, info = {}) => driveSync.markDownloaded(app, info));
  ipcMain.handle("drive:uploadBackup", async (_event, content) => driveSync.uploadBackup(app, String(content || "")));
  ipcMain.handle("drive:downloadBackup", async (_event, fileId = "") => driveSync.downloadBackup(app, String(fileId || "")));

  createWindow();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});
