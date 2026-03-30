# Rust MTR (My Traceroute) 🚀

一款由 Rust 编写的现代化、高并发终端网络诊断工具。它结合了 `traceroute` 和 `ping` 的功能，提供实时动态的路由节点追踪和网络延迟统计。

本工具针对 Windows 操作系统进行了深度重构与优化，完全弃用传统的 Raw Socket 提权模式，直接调用原生系统底层 API，**彻底解决 Windows 下必须以管理员身份运行的痛点**。

## ✨ 核心特性

* **跨平台原生发包引擎** ：
  * **Windows** ：直接调用系统底层 `IcmpSendEcho` API 穿透防火墙，普通用户免 `Administrator` 权限即可顺滑运行。
  * **Unix (Linux/macOS)** ：直连底层 Raw Socket，结合 Linux `cap_net_raw` 最小化特权架构，告别传统且具有提权风险的 SUID 与全局 `sudo` 依赖。
* **工业级报文溯源 (Sequence Matching)** ：在 Unix 引擎中彻底摒弃概率性启发式匹配。通过对 ICMP Time Exceeded (Type 11) 错误报文进行深度嵌套解包，精准提取内部封装的原始进程 Identifier 与 Sequence Number，在极端高并发与乱序网络下依然保证 100% 准确的节点匹配。
* **高并发探针模型** ：采用 Scatter-Gather (爆发发送-批量收集) 并发模型，消除遇到“禁 Ping”防火墙节点时的串行阻塞等待，瞬间渲染出完整的网络路由拓扑。
* **精美 TUI 交互界面** ：基于 `ratatui` 和 `crossterm` 构建，支持 10FPS 丝滑刷新的终端数据表格。启用备用屏幕 (Alternate Screen) 渲染，退出时自动恢复终端原貌，绝不污染命令历史。
* **智能 DNS 反向解析** ：后台独立线程异步处理 PTR 记录查询，不阻塞发包与界面主循环，自动将 IP 转换为易读的 Hostname。

## 📦 安装指南

### 方式一：下载预编译程序 (推荐)

前往项目的 [Releases 页面](https://github.com/antstars/mtr/releases) 下载最新版本的二进制可执行文件（如 `mtr-windows-amd64.exe或mtr-linux-amd64`），无需安装任何依赖，直接在终端中运行即可。

### 方式二：源码编译与一键特权部署 (Linux/macOS 推荐)

如果你已经安装了 Rust 工具链，可以直接克隆本仓库并进行 Release 级别最高优化编译。对于 Linux 用户，强烈推荐使用内置的部署脚本，它会自动为二进制文件注入内核级网络特权，实现长期的免密运行：

```bash
git clone https://github.com/antstars/mtr.git
cd mtr

# 执行部署脚本 (自动执行 cargo build --release 并配置 Linux Capabilities)
chmod +x install.sh
./install.sh
```

编译后的独立可执行程序位于 `target/release/mtr`。

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

本项目严格遵循高级软件工程与系统级安全规范：

* **SOLID & SRP** ：UI 渲染层、后台 DNS 解析层与并发网络探测引擎（基于 `mpsc::channel` 通信）完全解耦，职责边界清晰。
* **KISS (保持简单)** ：摒弃臃肿的庞大异步运行时（如 Tokio），采用原生 `std::thread` 配合无锁原子变量 (`AtomicBool`, `AtomicU8`) 进行极其轻量、低延迟的跨线程状态同步。
* **防御性内存安全** ：默认所有到达网卡的外部数据包皆不可信。在 Unix 网络解析核心循环中做到 Zero-Unwrap，引入严格的切片边界校验（Bounds Checking）与底层内存状态转换安全控制（处理 `MaybeUninit`），彻底杜绝畸形注入数据包引发的未定义行为 (UB) 和进程崩溃。
* **Fail-Fast 预检** ：在启动阶段对 CLI 输入参数进行严格的合法性与网络连通性预检，拒绝脏数据污染终端界面。
* **内核资源管理** ：在极高频的并发发包循环中，强制利用 RAII 机制或 `IcmpCloseHandle` 释放内核句柄，杜绝系统资源与文件描述符泄漏风险。

## 📄 开源协议

本项目基于 [MIT License](https://github.com/antstars/mtr?tab=MIT-1-ov-file#) 协议开源。
