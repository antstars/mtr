

# Rust MTR (My Traceroute) 🚀

一款由 Rust 编写的现代化、高并发终端网络诊断工具。它结合了 `traceroute` 和 `ping` 的功能，提供实时动态的路由节点追踪和网络延迟统计。

本工具针对 Windows 操作系统进行了深度重构与优化，完全弃用传统的 Raw Socket 提权模式，直接调用原生系统底层 API，**彻底解决 Windows 下必须以管理员身份运行的痛点**。

## ✨ 核心特性

* **开箱即用 (Windows 免权限)**：调用底层 `IcmpSendEcho` API，穿透防火墙拦截，普通用户即可直接运行，无需 `Administrator` 权限。
* **高并发发包引擎**：采用 Scatter-Gather 并发模型，消除遇到“禁 Ping”防火墙节点时的串行阻塞等待，瞬间渲染完整路由表。
* **精美 TUI 交互界面**：基于 `ratatui` 和 `crossterm` 构建 10FPS 丝滑刷新的终端表格，支持备用屏幕渲染，退出不污染命令历史。
* **智能 DNS 反向解析**：后台独立线程异步处理 PTR 记录查询，不阻塞发包与界面渲染，自动将 IP 转换为易读的 Hostname。
* **实时状态控制**：内置快捷键热响应，支持一键暂停探测或重置统计数据。

## 📦 安装指南

### 方式一：下载预编译程序 (推荐)

前往项目的 [Releases 页面](https://github.com/antstars/mtr/releases) 下载最新版本的二进制可执行文件（如 `mtr-windows-amd64.exe`），无需安装任何依赖，直接在终端中运行即可。

### 方式二：通过 Cargo 源码编译

如果你已经安装了 Rust 工具链，可以直接克隆本仓库并编译：

```bash
git clone https://github.com/antstars/mtr.git
cd mtr
cargo build --release
```

编译后的程序位于 `target/release/mtr.exe`。

## 🚀 使用说明

在终端中执行程序并传入目标域名或 IP 地址：

**Bash**

```
# 探测域名 (自动进行前置解析验证)
mtr baidu.com

# 直接探测 IPv4 地址
mtr 39.156.66.10
```

### ⌨️ 界面快捷键操作

进入 TUI 界面后，你可以使用以下快捷键进行实时交互：

| **快捷键**   | **功能说明**                                                            |
| ------------------ | ----------------------------------------------------------------------------- |
| `p`              | **Pause / Resume** ：暂停或恢复网络探测引擎的发包动作。                 |
| `r`              | **Restart** ：一键重置所有路由节点的 `Snt`、`Loss%`及延迟统计数据。 |
| `q`或 `Ctrl+C` | **Quit** ：安全释放系统内核资源，优雅退出程序。                         |

## 🛠️ 技术架构与设计原则

本项目严格遵循高质量软件工程规范：

* **SOLID & SRP** ：UI 渲染层、后台 DNS 解析层与并发网络探测引擎完全解耦。
* **KISS** ：摒弃臃肿的庞大异步运行时（如 Tokio），采用原生 `std::thread` 配合无锁原子变量 (`AtomicBool`, `AtomicU8`) 与 Channel 进行轻量级跨线程通信。
* **Fail-Fast 防御性编程** ：在启动阶段对 CLI 输入参数进行严格的合法性与网络连通性预检，拒绝脏数据污染终端界面。
* **内存与资源安全** ：在极高频的并发发包循环中，强制利用 `IcmpCloseHandle` 释放内核句柄，杜绝系统资源泄漏风险。

## 📄 开源协议

本项目基于 [MIT License](https://www.google.com/search?q=LICENSE&authuser=2) 协议开源。
