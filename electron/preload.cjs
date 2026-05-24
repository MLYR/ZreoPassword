const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("desktopBridge", {
  platform: process.platform,
  isElectron: true,
  openExternal: (url) => ipcRenderer.invoke("desktop:openExternal", url),
  saveTextFile: (options) => ipcRenderer.invoke("desktop:saveTextFile", options),
  readTextFile: (options) => ipcRenderer.invoke("desktop:readTextFile", options),
  pickFile: (options) => ipcRenderer.invoke("desktop:pickFile", options),
  pickAndReadTextFile: (options) => ipcRenderer.invoke("desktop:pickAndReadTextFile", options),
  vault: {
    getMeta: () => ipcRenderer.invoke("vault:getMeta"),
    initialize: (meta) => ipcRenderer.invoke("vault:initialize", meta),
    updateMeta: (meta) => ipcRenderer.invoke("vault:updateMeta", meta),
    hasRecords: () => ipcRenderer.invoke("vault:hasRecords"),
    listRecords: () => ipcRenderer.invoke("vault:listRecords"),
    replaceAllRecords: (records) => ipcRenderer.invoke("vault:replaceAllRecords", records),
    replaceAllRecordsWithMeta: (records, meta) => ipcRenderer.invoke("vault:replaceAllRecordsWithMeta", records, meta),
    upsertRecords: (records) => ipcRenderer.invoke("vault:upsertRecords", records),
    deleteRecords: (ids) => ipcRenderer.invoke("vault:deleteRecords", ids),
    getSetting: (key) => ipcRenderer.invoke("vault:getSetting", key),
    setSetting: (key, value) => ipcRenderer.invoke("vault:setSetting", key, value)
  },
  drive: {
    getStatus: () => ipcRenderer.invoke("drive:getStatus"),
    connect: () => ipcRenderer.invoke("drive:connect"),
    disconnect: () => ipcRenderer.invoke("drive:disconnect"),
    deleteBackup: (fileId) => ipcRenderer.invoke("drive:deleteBackup", fileId),
    getRemoteState: () => ipcRenderer.invoke("drive:getRemoteState"),
    listBackups: () => ipcRenderer.invoke("drive:listBackups"),
    markDownloaded: (info) => ipcRenderer.invoke("drive:markDownloaded", info),
    uploadBackup: (content) => ipcRenderer.invoke("drive:uploadBackup", content),
    downloadBackup: (fileId) => ipcRenderer.invoke("drive:downloadBackup", fileId)
  },
  onAction: (callback) => {
    const handler = (_event, action) => callback(action);
    ipcRenderer.on("desktop:action", handler);
    return () => ipcRenderer.removeListener("desktop:action", handler);
  }
});
