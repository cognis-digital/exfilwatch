# Ports of exfilwatch

The EXFILWATCH **core check** ported across languages so you can drop it into any
stack or ship a single static binary. Every port reads newline-delimited JSON log
events (`ts`, `src`, `dst`, `proto`, `query`) and flags DNS exfiltration
indicators — high **Shannon entropy** in DNS labels (encoded payload) and
**oversized DNS names** (tunnelling) — emitting the same JSON shape:

```json
{ "tool": "exfilwatch", "findings": [ { "detector": "...", "severity": "...", "src": "...", "dst": "...", "score": 0.0, "summary": "..." } ], "score": 1 }
```

All ports are **passive / offline** (no network). Exit code `2` when findings
exist, `0` when clean — matching the Python reference.

| Language | Path | Run | Test |
|---|---|---|---|
| Python (reference) | `../exfilwatch/` | `exfilwatch scan log.jsonl` | `python -m pytest` |
| JavaScript / Node | `javascript/` | `node ports/javascript/index.js log.jsonl` | `node --test` |
| Go | `go/` | `cd ports/go && go run . log.jsonl` | `go test ./...` |
| Rust | `rust/` | `cd ports/rust && cargo run -- log.jsonl` | `cargo test` |

The JavaScript port is verified locally; the Go and Rust ports are built and
tested on GitHub runners by `.github/workflows/ports.yml` (the maintainer's dev
box does not have the Go/Rust toolchains installed).

Contributions of additional ports (Ruby, C#, Bun, Deno, WASM) are welcome — see
../CONTRIBUTING.md.
