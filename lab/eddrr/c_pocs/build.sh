#!/usr/bin/env sh
set -eu

CC=${CC:-cc}
CFLAGS="-std=c11 -Wall -Wextra -O2"

for src in poc_r*.c; do
    exe="${src%.c}"
    "$CC" $CFLAGS "$src" -o "$exe"
    printf 'built %s\n' "$exe"
done
