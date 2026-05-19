const { app, BrowserWindow, Menu, dialog, shell, ipcMain } = require("electron");
const path = require("path");
const fs = require("fs/promises");

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
  return [{ name: "All Files", extensions: ["*"] }];
}

function resolveSaveOptions(options = {}) {
  return {
    defaultPath: options.defaultPath || "export.html",
    title: options.title || "保存文件",
    filters: mimeToFilter(options.mimeType)
  };
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
    if (typeof filePath !== "string" || !filePath.trim()) {
      return { canceled: true };
    }
    const stat = await fs.stat(filePath);
    if (typeof options.maxBytes === "number" && options.maxBytes > 0 && stat.size > options.maxBytes) {
      return { canceled: false, tooLarge: true, filePath, size: stat.size };
    }
    const content = await fs.readFile(filePath, "utf8");
    return { canceled: false, filePath, content, size: stat.size };
  });

  ipcMain.handle("desktop:pickFile", async (_event, options = {}) => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: options.title || "选择文件",
      properties: ["openFile"],
      filters: options.filters || [
        { name: "HTML", extensions: ["html", "htm"] },
        { name: "JSON", extensions: ["json"] },
        { name: "All Files", extensions: ["*"] }
      ]
    });
    if (result.canceled || !result.filePaths.length) {
      return { canceled: true };
    }
    return { canceled: false, filePaths: result.filePaths };
  });

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
