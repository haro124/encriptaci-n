#!/usr/bin/env bash
# Lanzador para Linux (CachyOS / Arch). Uso: ./iniciar_demo.sh
cd "$(dirname "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
    echo "No se encontró Python 3. Instálalo con:  sudo pacman -S python"
    exit 1
fi
exec python3 lanzar_demo.py "$@"
