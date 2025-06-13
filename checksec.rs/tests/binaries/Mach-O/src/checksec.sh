#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage $0 <binary>"
    exit 1
fi

BIN="$1"

if [ ! -f "$BIN" ]; then
    echo "File not found: $BIN"
    exit 1
fi

printf "File: $BIN\t"

# Mach-O 64
ARCH=$(otool -hv "$BIN" | grep "MH_MAGIC_64")
if [ -n "$ARCH" ]; then
    printf "MachO64: true\t"
else
    printf "MachO64: false\t"
fi

IMPORTS=$(nm -u "$BIN" 2>/dev/null | grep '_objc_alloc')
if [ -n "$IMPORTS" ]; then
    HAS_ARC="true"
else
    HAS_ARC="false"
fi
printf "ARC: $HAS_ARC\t"

# PIE
PIE=$(otool -hv "$BIN" | grep PIE)
if [ -n "$PIE" ]; then
    printf "PIE: true\t"
else
    printf "PIE: false\t"
fi

# Code Signature
CSIG=$(otool -l "$BIN" | grep LC_CODE_SIGNATURE)
if [ -n "$CSIG" ]; then
    printf "Code Signature: true\t"
else
    printf "Code Signature: false\t"
fi

# Encrypted
ENCRYPT=$(otool -l "$BIN" | grep -A 5 LC_ENCRYPTION_INFO_64 | grep cryptid | awk '{print $2}')
if [ "$ENCRYPT" = "0" ]; then
    printf "Encrypted: false\t"
elif [ -n "$ENCRYPT" ]; then
    printf "Encrypted: true\t"
else
    printf "Encrypted: false\t"
fi

# FORTIFY checks (_chk symbols)
FORTIFY_COUNT=$(nm "$BIN" 2>/dev/null | grep -E '[_a-zA-Z0-9]+_chk$' | wc -l | tr -d ' ')
if [ "$FORTIFY_COUNT" -gt 0 ]; then
    HAS_FORTIFY="true"
else
    HAS_FORTIFY="false"
fi
printf "Fortify: $HAS_FORTIFY\t"
printf "Fortified: $FORTIFY_COUNT\t"

# NX Stack
HEADER="$(otool -h "$BIN" | grep '^ 0x')"
FLAGS_HEX=$(echo "$HEADER" | awk '{print $8}')
FLAGS_DEC=$((FLAGS_HEX))

# NX Heap y NX Stack via flags
# NX Heap: check MH_NO_HEAP_EXECUTION (0x01000000)
# NX Stack: check absence of MH_ALLOW_STACK_EXECUTION (0x00020000)
(( (FLAGS_DEC & 0x01000000) != 0 )) && NXHEAP="true" || NXHEAP="false"
(( (FLAGS_DEC & 0x00020000) == 0 )) && NXSTACK="true" || NXSTACK="false"

printf "NX Heap: $NXHEAP\t"
printf "NX Stack: $NXSTACK\t"

# Stack Canary
CANARY=$(nm "$BIN" 2>/dev/null | grep stack_chk_fail)
if [ -n "$CANARY" ]; then
    printf "Canary: true\t"
else
    printf "Canary: false\t"
fi

# Restrict
RESTRICT=$(otool -l "$BIN" | grep -A1 "segname" | grep -w '__restrict')
printf "Restrict: "
[ -n "$RESTRICT" ] && printf "true\t" || printf "false\t"

# RPath
RPATH=$(otool -l "$BIN" | grep LC_RPATH)
if [ -n "$RPATH" ]; then
    printf "RPath: true\n"
else
    printf "RPath: false\n"
fi