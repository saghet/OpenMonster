#!/usr/bin/env bash
# SECMASTER-OpenMonster Application Launcher
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BINARY="$SCRIPT_DIR/src-tauri/target/release/sec-master"

if [ ! -f "$BINARY" ]; then
    echo "[!] Binario no encontrado en $BINARY. Compilando..."
    cargo build --release --manifest-path "$SCRIPT_DIR/src-tauri/Cargo.toml"
fi

echo "[*] Iniciando SECMASTER-OpenMonster..."
exec "$BINARY" "$@"
