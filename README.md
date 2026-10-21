# Rust MTR (My Traceroute) 🚀

运行时如果缺少 `cap_net_raw`，TUI 顶部会显示高亮警告，并给出针对当前可执行文件的 `sudo setcap cap_net_raw+ep ...` 命令。程序不会自动执行 `sudo`；降级到 Datagram 模式时，中间跳点可能显示为 `???`，两种 socket 都不可用时则显示错误和修复建议。

一款由 Rust 编写的现代化、高并发终端网络诊断工具。它结合了 `traceroute` 和 `ping` 的功能，提供实时动态的路由节点追踪和网络延迟统计。

本工具针对 Windows 操作系统进行了深度重构与优化，完全弃用传统的 Raw Socket 提权模式，直接调用原生系统底层 API，**彻底解决 Windows 下必须以管理员身份运行的痛点**。

## ✨ 核心特性

* **跨平台原生发包引擎** ：
  * **Windows** ：直接调用系统底层 `IcmpSendEcho` API 穿透防火墙，普通用户免 `Administrator` 权限即可顺滑运行。
  * **Unix (Linux/macOS)** ：支持 IPv4 和 IPv6 ICMP 探测；IPv4 优先使用 Raw Socket，并可在权限不足时降级到 Datagram Socket。Linux 使用 `cap_net_raw` 即可授予最小必要权限。
* **工业级报文溯源 (Sequence Matching)** ：在 Unix 引擎中彻底摒弃概率性启发式匹配。通过对 ICMP Time Exceeded (Type 11) 错误报文进行深度嵌套解包，精准提取内部封装的原始进程 Identifier 与 Sequence Number，在极端高并发与乱序网络下依然保证 100% 准确的节点匹配。
* **高并发探针模型** ：采用 Scatter-Gather (爆发发送-批量收集) 并发模型，消除遇到“禁 Ping”防火墙节点时的串行阻塞等待，瞬间渲染出完整的网络路由拓扑。
* **精美 TUI 交互界面** ：基于 `ratatui` 和 `crossterm` 构建，支持 10FPS 丝滑刷新的终端数据表格。启用备用屏幕 (Alternate Screen) 渲染，退出时自动恢复终端原貌，绝不污染命令历史。
* **智能 DNS 反向解析** ：后台独立线程异步处理 PTR 记录查询，不阻塞发包与界面主循环，自动将 IP 转换为易读的 Hostname。
* **报告模式** ：支持指定探测轮数、探测间隔和最大跳数，输出适合脚本或终端保存的文本报告。

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

# 探测 IPv6 地址（Unix 系统）
mtr --ipv6 2001:4860:4860::8888
```

常用命令行选项：

```bash
# 运行 10 轮并输出文本报告，不进入 TUI
mtr --report example.com

# 运行 20 轮、每轮间隔 0.8 秒，最多探测 20 跳
mtr --report --report-cycles 20 --interval 0.8 --max-hops 20 example.com

# 禁用反向 DNS，仅显示 IP 地址
mtr --no-dns example.com

# 强制使用 IPv4；IPv4/IPv6 参数不能同时使用
mtr --ipv4 example.com
```

`--report-cycles` 必须与 `--report` 一起使用；探测间隔不能小于 0.8 秒（单轮收包超时为 800ms）。`--ipv6` 要求目标解析为 IPv6 地址，链路本地 IPv6 地址（`fe80::/10`）目前不支持接口作用域。Unix 系统支持 IPv6 探测，Windows 当前仅支持 IPv4 ICMP 探测。

### Linux：`sudo` 与 `???` 节点说明

在 Linux 上，`???` 表示该 TTL 未收到可匹配的路由节点 IP，并不表示 DNS 反向解析失败；DNS 解析失败时，界面仍会显示对应 IP 地址。

本程序需要接收路由器返回的 ICMP `Time Exceeded` 报文来识别中间跳点。使用 `sudo` 时，程序可创建 Raw ICMP socket，因此能够显示中间节点。普通用户运行时，若没有 `cap_net_raw` 权限，程序会降级为 Linux 的 ICMP ping socket；该模式仅能识别目标主机的 Echo Reply，无法显示中间路由器的节点，于是前几跳会显示为 `???`。

推荐通过安装脚本授予可执行文件最小必要权限，而不是每次以 `sudo` 运行：

```bash
./install.sh
getcap /usr/local/bin/mtr

# 预期包含：/usr/local/bin/mtr cap_net_raw=ep
mtr <目标地址>
```

如果直接运行本地编译产物，请为该文件单独设置 capability：

```bash
sudo setcap cap_net_raw+ep ./target/release/mtr
getcap ./target/release/mtr
./target/release/mtr <目标地址>
```

每次重新编译或替换二进制文件后，通常需要重新设置 capability。仅配置 `net.ipv4.ping_group_range` 只能允许非特权 ping socket，不能让当前程序获取中间路由器的 ICMP `Time Exceeded` 回包。

### ⌨️ 界面快捷键操作

进入 TUI 界面后，你可以使用以下快捷键进行实时交互：

| **快捷键**   | **功能说明**                                                            |
| ------------------ | ----------------------------------------------------------------------------- |
| `p`              | **Pause / Resume** ：暂停或恢复网络探测引擎的发包动作。                 |
| `r`              | **Restart** ：一键重置所有路由节点的 `Snt`、`Loss%`及延迟统计数据。 |
| `n`              | **DNS** ：切换反向 DNS 名称显示；使用 `--no-dns` 启动时不可用。       |
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
