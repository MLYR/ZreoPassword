# 小〇密码

小〇密码是一个本地优先的密码管理器，目前包含网页 MVP 和 Electron 桌面端框架。项目不依赖后端服务，桌面端主存储已经改为 SQLite，本地敏感数据继续使用 WebCrypto AES-GCM 加密。

## 当前状态

- 网页模式：使用浏览器 `localStorage` 作为 fallback。
- 桌面模式：使用 Electron + SQLite，数据库文件位于系统用户数据目录。
- 加密方式：PBKDF2 派生密钥，AES-GCM 加密数据。
- 桌面端记录按单条加密保存，避免大数据量时整库重写。

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
- Chrome 密码 CSV 导入，支持同域名多账号
- 旧版加密 JSON vault 兼容导入 / 迁移
- macOS / Windows 打包配置

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
- 记录的敏感字段在 `encryptedContent` 中加密保存。
- 数据库文件只由 Electron 主进程访问，前端通过受控 IPC 调用。

### 网页模式

网页模式仍使用：

```text
localStorage -> zreo-password-vault-v1
```

该模式主要用于开发和预览。真正桌面软件以 SQLite 为主。

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

说明：`npm run dev` 只启动网页服务；`npm run desktop` 才会打开 Electron 桌面程序。

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
- 当前未接入系统钥匙串；后续可接 macOS Keychain / Windows Credential Manager。
- 当前暂未使用 SQLCipher，数据库中敏感字段由应用层 AES-GCM 加密。

## 后续方向

- SQLite 查询层分页和虚拟列表，支持更大数据量
- 导入任务进度条和可取消导入
- 系统托盘和后台自动锁定
- 数据库备份 / 恢复
- WebDAV、Dropbox、Google Drive 等同步能力
- macOS Keychain / Windows Credential Manager 集成
