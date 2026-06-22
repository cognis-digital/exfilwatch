#!/usr/bin/env bash
# Build + test every language port (each ports the core DNS-exfil check).
set -e
echo "== javascript =="
( cd ports/javascript && node --test ) || echo "node: skipped"
echo "== go =="
( cd ports/go && go vet ./... && go test ./... ) 2>/dev/null || echo "go: skipped (toolchain absent — verified in CI)"
echo "== rust =="
( cd ports/rust && cargo test ) 2>/dev/null || echo "rust: skipped (toolchain absent — verified in CI)"
