# 小〇密码

本项目是根据 `小〇密码.pages` 需求文档先落地的网页 MVP，同时已经补了 Electron 桌面框架骨架。当前以静态页面为核心，不依赖后端，核心数据使用浏览器本地存储，并通过 WebCrypto 做 AES-GCM 加密。

## 已实现

- 主密码创建 / 解锁 / 锁定
- 当前标签页不关闭时，刷新页面会自动恢复解锁状态
- 设置面板：导入、导出、修改主密码、后续登录能力占位
- AES-GCM + PBKDF2 本地加密保存
- 密码记录新增、编辑、删除
- 同一标题支持多账号记录，列表会按标题分组展示
- 支持账号密码、Google、微信、GitHub、Apple 等登录方式标识
- 支持标签 / 环境字段，例如个人、公司、测试、客户A
- 密码字段可留空，适配第三方登录记录
- 密码查看 / 隐藏切换
- 双击记录列表可打开对应网址
- 分类筛选、关键词搜索、排序
- 密码强度提示、重复密码统计、最近更新统计
- 密码生成器
- 复制用户名 / 网址 / 密码
- Google / Chrome 书签 HTML 导入导出
- 旧版加密 JSON 备份兼容导入
- Electron 桌面框架骨架，后续可直接打包 macOS / Windows

## 本地运行

直接打开 `index.html` 可以预览。为了让 WebCrypto、剪贴板等浏览器能力更稳定，推荐在目录里启动本地服务：

```bash
python3 -m http.server 5173
```

然后访问：

```text
http://localhost:5173
```

## 桌面端运行与打包

项目已经补了 Electron 框架骨架，后续可直接往 macOS / Windows 桌面程序方向走。

先安装依赖：

```bash
npm install
```

启动桌面版开发：

```bash
npm run dev
```

打包 macOS：

```bash
npm run dist:mac
```

打包 Windows：

```bash
npm run dist:win
```

说明：
- `dev` 现在是桌面壳模式，代码改动后通常需要刷新窗口；Electron 主进程文件改动时需要重启应用。
- 书签 HTML 只负责导入导出站点结构，不包含密码数据。

## 后续桌面端方向

当前已经有 Electron 桌面框架骨架，后续主要继续补系统托盘、自动锁定、文件备份、WebDAV / Dropbox / Drive 同步等能力。
