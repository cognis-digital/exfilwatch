<a name="top"></a>
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=EXFILWATCH&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="EXFILWATCH"/>

# EXFILWATCH

### Detect DNS/HTTP exfiltration patterns (entropy, beaconing) in logs

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Detect+DNSHTTP+exfiltration+patterns+entropy+beaconing+in+lo;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>

[![PyPI](https://img.shields.io/pypi/v/cognis-exfilwatch.svg?color=6b46c1)](https://pypi.org/project/cognis-exfilwatch/) [![CI](https://github.com/cognis-digital/exfilwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/exfilwatch/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

*Part of the Cognis Neural Suite.*

</div>

```bash
pip install cognis-exfilwatch
exfilwatch scan .            # → prioritized findings in seconds
```

## Usage — step by step

1. **Install** the CLI:

   ```bash
   pipx install "git+https://github.com/cognis-digital/exfilwatch.git"
   ```

2. **Scan** a newline-delimited JSON (JSONL) log for exfiltration signals — the primary command. Pass a path or `-` for stdin:

   ```bash
   exfilwatch scan netflow.jsonl
   cat netflow.jsonl | exfilwatch scan -
   ```

3. **Tune detectors** — DNS-tunneling entropy, beaconing regularity, and oversized-DNS length:

   ```bash
   exfilwatch scan netflow.jsonl \
     --entropy-threshold 3.8 --beacon-min-events 6 --beacon-max-jitter 0.1 --dns-max-len 48
   ```

4. **Read the output** — a table by default, JSON for SIEM ingestion, or SARIF for code-scanning/CI:

   ```bash
   exfilwatch scan netflow.jsonl --format json  > alerts.json
   exfilwatch scan netflow.jsonl --format sarif > exfilwatch.sarif   # upload to GitHub code scanning
   ```

5. **Automate in a pipeline** — pull beaconing alerts from JSON:

   ```bash
   exfilwatch scan netflow.jsonl --format json | jq '.[] | select(.kind=="beacon")'
   ```

## Contents

- [Why exfilwatch?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)

<a name="why"></a>
## Why exfilwatch?

catch beacons

`exfilwatch` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="features"></a>
## Features

- ✅ Shannon Entropy
- ✅ Parse Log
- ✅ Detect Entropy
- ✅ Detect Beaconing
- ✅ Detect Long Dns
- ✅ Analyze
- ✅ Output as table · JSON · **SARIF 2.1.0** (GitHub code-scanning ready)
- ✅ Reads epoch **and** ISO-8601 timestamps; path or stdin (`-`)
- ✅ 10 ready-to-run [demo scenarios](#demos) (real JSONL, verified in CI)
- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer
- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="quick-start"></a>
## Quick start

```bash
pip install cognis-exfilwatch
exfilwatch --version
exfilwatch scan .                       # scan current project
exfilwatch scan . --format json         # machine-readable
exfilwatch scan . --fail-on high        # CI gate (non-zero exit)
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="example"></a>
## Example

```text
$ exfilwatch scan .
  [HIGH    ] EXF-001  example finding             (./src/app.py)
  [MEDIUM  ] EXF-002  another signal              (./config.yaml)

  2 findings · risk score 5 · 38ms
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="demos"></a>
## Demos

Ten self-contained scenarios live in [`demos/`](demos/). Each is a real JSONL
log plus a `SCENARIO.md` narrative (where the data came from, the exact command,
and how to act). Every demo's documented outcome is asserted in the test suite,
so they never rot. Run any of them straight from a clone:

| # | Scenario | What it shows | Fires? |
|---|---|---|:---:|
| [01](demos/01-basic/) | Basic triage | tunnel + beacon + benign noise | ✅ |
| [02](demos/02-clean/) | Clean baseline | known-good traffic → silent | — clean |
| [03](demos/03-mixed/) | Beacon in noise | one C2 buried in browsing | ✅ |
| [04](demos/04-dns-tunnel-bulk/) | DNS tunnel | sustained base32 exfil (entropy + long_dns) | ✅ |
| [05](demos/05-http-beacon-jitter/) | C2 heartbeat | 10-min beacon with jitter | ✅ |
| [06](demos/06-iso8601-timestamps/) | SIEM export | ISO-8601 timestamps parse fine | ✅ |
| [07](demos/07-http-path-exfil/) | HTTP path exfil | base64 blobs in URL paths | ✅ |
| [08](demos/08-multi-host-fanout/) | Botnet fan-out | 4 hosts → one shared C2 | ✅ |
| [09](demos/09-stdin-pipe/) | Streaming | scan from stdin (`scan -`) | ✅ |
| [10](demos/10-tuning-fp/) | Threshold tuning | legit CDN; avoiding false positives | — clean |

```bash
python -m exfilwatch scan demos/04-dns-tunnel-bulk/events.jsonl
cat demos/09-stdin-pipe/events.jsonl | python -m exfilwatch scan - --format json
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>
## Architecture

```mermaid
flowchart LR
  IN[target / export] --> P[exfilwatch<br/>collect + correlate]
  P --> OUT[ranked findings]
```

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="ai-stack"></a>
## Use it from any AI stack

`exfilwatch` is interoperable with every popular way of using AI:

- **MCP server** — `exfilwatch mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))
- **OpenAI-compatible / JSON** — pipe `exfilwatch scan . --format json` into any agent or LLM
- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line
- **CI / scripts** — exit codes + SARIF for non-AI pipelines

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="how-it-compares"></a>
## How it compares

| | **Cognis exfilwatch** | RITA |
|---|:---:|:---:|
| Self-hostable, no account | ✅ | varies |
| Single command, zero config | ✅ | ⚠️ |
| JSON + SARIF for CI | ✅ | varies |
| MCP-native (AI agents) | ✅ | ❌ |
| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |
| Open license | ✅ COCL | varies |

*Built in the spirit of **RITA**, re-framed the Cognis way. Missing a credit? Open a PR.*

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="integrations"></a>
## Integrations

Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`exfilwatch mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="install-anywhere"></a>
## Install — every way, every platform

```bash
pip install "git+https://github.com/cognis-digital/exfilwatch.git"    # pip (works today)
pipx install "git+https://github.com/cognis-digital/exfilwatch.git"   # isolated CLI
uv tool install "git+https://github.com/cognis-digital/exfilwatch.git" # uv
pip install cognis-exfilwatch                                          # PyPI (when published)
docker run --rm ghcr.io/cognis-digital/exfilwatch:latest --help        # Docker
brew install cognis-digital/tap/exfilwatch                             # Homebrew tap
curl -fsSL https://raw.githubusercontent.com/cognis-digital/exfilwatch/main/install.sh | sh
```

| Linux | macOS | Windows | Docker | Cloud |
|---|---|---|---|---|
| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/exfilwatch` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="related"></a>
## Related Cognis tools

- [`portfan`](https://github.com/cognis-digital/portfan) — Summarize and diff nmap XML into prioritized, attackable findings
- [`subhunt`](https://github.com/cognis-digital/subhunt) — Aggregate & dedupe subdomain enumeration from multiple sources
- [`dirsight`](https://github.com/cognis-digital/dirsight) — Analyze web content-discovery output (ffuf/gobuster) into ranked endpoints
- [`jwtinspect`](https://github.com/cognis-digital/jwtinspect) — Decode JWTs and lint for alg=none, weak secrets, and missing claims
- [`corsaudit`](https://github.com/cognis-digital/corsaudit) — Detect permissive/misconfigured CORS from headers or a config
- [`headerscan`](https://github.com/cognis-digital/headerscan) — Grade HTTP security headers (CSP/HSTS/XFO) A-F from a response dump

**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="contributing"></a>
## Contributing

PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

> ### ⭐ If `exfilwatch` saved you time, **star it** — it genuinely helps others find it.

## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).

---

<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>
