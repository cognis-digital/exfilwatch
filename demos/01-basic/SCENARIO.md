# Demo 01 - Basic DNS/HTTP Exfiltration Triage

This scenario exercises all three EXFILWATCH detectors against a small,
realistic JSONL log captured from an **authorized** internal sensor.

## The log: `events.jsonl`

Newline-delimited JSON. Each event has `ts` (epoch seconds), `src`, `dst`,
`proto` (`dns`/`http`), an optional `query` (DNS name or HTTP path), and
optional `bytes`.

## What's hidden in the data

1. **DNS tunneling (`10.0.0.50` -> `evil-tunnel.example.net`)**
   - High-entropy base32-looking labels: `mfrggzdfmztwq2lk...`
   - Oversized query names well past 52 characters.
   - Triggers both the `entropy` and `long_dns` detectors.

2. **C2 beaconing (`10.0.0.50` -> `cdn-metrics.example.io`)**
   - HTTP callbacks every ~60 seconds with near-zero jitter.
   - Triggers the `beaconing` detector.

3. **Benign noise (`10.0.0.12` -> `www.example.com`)**
   - Normal-entropy, irregular web browsing. Should NOT be flagged.

## Run it

```sh
# Human-readable table
python -m exfilwatch scan demos/01-basic/events.jsonl

# Machine-readable JSON (for SIEM / pipeline ingestion)
python -m exfilwatch scan demos/01-basic/events.jsonl --format json
```

## Expected outcome

- Exit code **2** (findings detected).
- Findings for the DNS tunnel (entropy + long_dns) and the HTTP beacon.
- No finding for the benign `10.0.0.12` browsing traffic.

> EXFILWATCH is detection/triage only. It reads logs and reports indicators.
> It performs no network activity and has no attack capability.
