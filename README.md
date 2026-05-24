# 小〇密码

小〇密码是一个本地优先的密码管理器，当前包含网页预览版和 Electron 桌面端框架。桌面端主存储使用 SQLite，敏感内容继续使用 WebCrypto AES-GCM 加密，不依赖后端服务。

## 当前状态

| 模式 | 存储 | 用途 |
| --- | --- | --- |
| 网页模式 | `localStorage` | 开发预览 / fallback |
| 桌面模式 | SQLite + 单条记录加密 | 后续 macOS / Windows 软件主形态 |

说明：

- 桌面端数据库放在系统用户数据目录。
- 记录按单条加密保存，新增、编辑、删除不会每次重写整库。
- 主密码只保存在当前页面内存中，手动锁定或自动锁定后需要重新输入。

## 已实现功能

- 主密码创建、解锁、手动锁定、空闲自动锁定
- 密码记录新增、编辑、删除、批量删除
- 分类筛选、分类右键重命名 / 删除
- 同标题多账号分组展示
- 支持账号密码、Google、微信、GitHub、Apple、手机号等登录方式标识
- 密码可留空，适配第三方登录记录
- 密码查看 / 隐藏切换
- 双击记录打开对应网址
- 关键词搜索、排序、密码强度提示、重复密码统计
- 密码生成器
- 复制用户名 / 密码
- Google / Chrome 书签 HTML 导入导出
- Chrome 密码 CSV 导入，按网址补全已有记录，支持同域名多账号
- 旧版加密 JSON vault 兼容导入 / 迁移
- Google Drive `appDataFolder` 加密备份同步
- macOS / Windows 打包配置

## 项目结构

```text
.
├── index.html              # 页面结构
├── styles.css              # 页面样式
├── app.js                  # 前端状态、加密、导入导出、交互逻辑
├── electron/
│   ├── main.cjs            # Electron 主进程、菜单、IPC、SQLite 接入
│   ├── preload.cjs         # 安全暴露给前端的桌面端能力
│   └── drive-sync.cjs      # Google Drive OAuth、token 刷新与备份同步
├── package.json            # 运行、打包配置
└── README.md
```

## 本地运行

安装依赖：

```bash
npm install
```

启动网页预览：

```bash
npm run dev
```

访问：

```text
http://localhost:5173
```

启动桌面端：

```bash
npm run desktop
```

注意：`npm run dev` 只启动网页服务；`npm run desktop` 才会打开 Electron 桌面程序。

## 数据存储

### 桌面端

桌面端使用 SQLite：

```text
~/Library/Application Support/zreo-password/vault.sqlite3
```

主要表：

```text
vault_meta
records
settings
```

说明：

- `vault_meta` 保存 salt、迭代次数、版本等元信息。
- `records` 保存记录索引字段和单条加密内容。
- `settings` 保存自动锁定时间等配置。
- 标题、网址、分类、标签、登录方式等列表检索字段会明文作为索引保存。
- 用户名、密码、备注等敏感字段保存在 `encryptedContent` 中。
- SQLite 文件只由 Electron 主进程访问，前端通过受控 IPC 调用。

### 网页模式

网页模式仍使用：

```text
localStorage -> zreo-password-vault-v1
```

该模式主要用于开发和预览。真正桌面软件以 SQLite 为主。

## 导入导出

### 书签 HTML

- 支持 Google / Chrome 常见 Netscape Bookmark HTML。
- 导入时会跳过 Chrome 最外层“书签栏”，直接从里面的文件夹开始。
- 文件夹路径会映射为应用里的分类 / 标签信息。
- 书签 HTML 只包含标题、网址、文件夹，不包含密码。

### Chrome 密码 CSV

- 支持 Chrome 标准表头：`name,url,username,password,note`。
- 只按网址补全已有记录，不会新建书签 / 记录。
- 同一域名下多个账号会尽量按用户名匹配。
- 多账号无法安全判断时会跳过，避免把密码写错记录。

### 加密备份 JSON

- 用于旧版 vault 兼容导入 / 迁移。
- 备份内容仍是加密数据，不是明文密码。

## Google Drive 同步

Google Drive 同步使用 `appDataFolder` 保存加密备份 JSON，不上传明文密码。

运行前需要在 Google Cloud 创建 OAuth Client，建议选择 Desktop app 类型。正式用户版不会让用户填写 OAuth 配置，应用会从项目配置或环境变量读取 Client ID 和 Client Secret。

项目内置配置入口：

```text
electron/google-oauth-config.cjs
```

本机开发或打包时可创建私有配置文件，不提交到 git：

```text
electron/google-oauth-private.cjs
```

配置格式：

```js
module.exports = {
  clientId: "你的 OAuth Client ID",
  clientSecret: "你的客户端密钥"
};
```

开发时也可以通过环境变量传入：

```bash
GOOGLE_DRIVE_CLIENT_ID="你的 OAuth Client ID" npm run desktop
```

如果 Google Cloud 页面显示了客户端密钥，也可以同时传入：

```bash
GOOGLE_DRIVE_CLIENT_ID="你的 OAuth Client ID" GOOGLE_DRIVE_CLIENT_SECRET="你的客户端密钥" npm run desktop
```

OAuth 授权范围：

```text
https://www.googleapis.com/auth/drive.appdata
```

同步文件名：

```text
zreo-password-backup-YYYY-MM-DD-HHmmss.json
```

说明：

- 上传时会用当前主密码生成加密备份后写入 Google Drive，每次上传都会新建一个带日期时间的备份文件，不覆盖旧备份。
- 恢复时会下载 Google Drive 中的加密备份，并用当前会话主密码解密。
- 如果当前主密码和备份不匹配，恢复会失败。
- Google OAuth Client ID 和 Client Secret 由应用配置提供；普通用户只需要点击连接并登录自己的 Google 账号。
- Google Drive 登录 token 会保存在 Electron 用户数据目录，重启应用后仍可继续同步。
- 上传 / 恢复成功后会记录本地同步状态，设置页会显示上次上传、上次恢复和云端更新时间。
- 设置页可以查看当前 Google 账号 `appDataFolder` 下的云端备份文件列表，并从指定备份恢复或删除指定云端备份。
- 当前是手动同步：上传前如果发现云端备份可能更新过，会先确认；恢复前如果发现本地库有新改动，也会先确认。
- 可在设置页开启“本地修改后自动上传加密备份”。该开关默认关闭；开启后本地保存会延迟上传，短时间多次修改只上传一次。
- 自动上传发现云端备份可能有新版本时会暂停，并提示用户手动确认，避免静默覆盖另一台设备的备份。
- Google API 请求有超时保护，网络异常时会回到错误提示，不会长期卡在同步状态。
- 设置页可以手动断开 Google Drive，断开后会删除本地保存的同步 token。
- 未配置 Client ID / Client Secret 时，同步入口会提示缺少项目配置。
- 当前 token 先落在用户数据目录，后续建议接入系统钥匙串进一步提高安全性。

## 打包

macOS：

```bash
npm run dist:mac
```

Windows x64：

```bash
npm run dist:win
```

Windows arm64：

```bash
npm run dist:win:arm64
```

全部打包：

```bash
npm run dist:all
```

## 原生依赖说明

项目使用 `better-sqlite3`。这是原生模块，Electron 版本变化后可能需要重新编译：

```bash
npm rebuild better-sqlite3 --runtime=electron --target=36.2.0 --disturl=https://electronjs.org/headers
```

如果普通 Node 直接 `require("better-sqlite3")` 出现 ABI 不匹配，而 Electron 能正常启动，通常是因为模块已经按 Electron ABI 编译。

## 安全说明

- 主密码不上传。
- 桌面端不再把主密码写入 `localStorage`。
- 手动锁定或自动锁定后会清空内存中的密钥和记录。
- 当前暂未使用 SQLCipher，数据库中敏感字段由应用层 AES-GCM 加密。
- Google Drive token 当前保存在 Electron 用户数据目录，后续可接 macOS Keychain / Windows Credential Manager。

## 后续方向

- SQLite 查询层分页和虚拟列表，支持更大数据量
- 导入任务进度条和可取消导入
- 系统托盘和后台自动锁定
- macOS Keychain / Windows Credential Manager 集成
- 自动同步策略、冲突处理、同步历史
- 完整 macOS / Windows 安装包验证
