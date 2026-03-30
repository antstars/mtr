#!/bin/bash
# install.sh
# 职责：编译 Release 版本，安装到系统路径，并赋予无密码执行的网络特权

set -e

echo "🚀 开始构建工业级 Rust MTR..."
cargo build --release

BIN_PATH="./target/release/mtr"
DEST_PATH="/usr/local/bin/rust-mtr"

echo "📦 正在将二进制文件安装到 $DEST_PATH..."
sudo cp "$BIN_PATH" "$DEST_PATH"

# 尝试使用现代的 Capabilities 方案
if command -v setcap >/dev/null 2>&1; then
    echo "🛡️ 检测到系统支持 Capabilities，正在授予网络底层的发包特权..."
    sudo setcap cap_net_raw+ep "$DEST_PATH"
    echo "✅ 部署完成！(模式: Capabilities)"
else
    # 优雅降级：如果没有 setcap 工具，回退到传统的 SUID 提权方案
    echo "⚠️ 系统未预装 setcap，正在优雅降级到 SUID 提权方案..."
    sudo chown root "$DEST_PATH"
    sudo chmod u+s "$DEST_PATH"
    echo "✅ 部署完成！(模式: SUID)"
fi

echo "🎉 一切就绪！现在你可以直接执行: rust-mtr <域名或IP>"