#!/usr/bin/env sh
set -eu

for exe in ./poc_r*; do
    case "$exe" in
        *.c|*.h) continue ;;
    esac
    printf '--- %s ---\n' "$exe"
    "$exe"
done
