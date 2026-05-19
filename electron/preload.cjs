const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("desktopBridge", {
  platform: process.platform,
  isElectron: true,
  openExternal: (url) => ipcRenderer.invoke("desktop:openExternal", url),
  saveTextFile: (options) => ipcRenderer.invoke("desktop:saveTextFile", options),
  readTextFile: (options) => ipcRenderer.invoke("desktop:readTextFile", options),
  pickFile: (options) => ipcRenderer.invoke("desktop:pickFile", options),
  onAction: (callback) => {
    const handler = (_event, action) => callback(action);
    ipcRenderer.on("desktop:action", handler);
    return () => ipcRenderer.removeListener("desktop:action", handler);
  }
});
