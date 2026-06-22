# Demo 09 - Streaming via stdin (pipeline-friendly)

EXFILWATCH reads from stdin with `-`, so you can chain it into `zcat`, `tail`,
`kubectl logs`, or a SIEM query without staging a file first.

## The log: `events.jsonl`

A small 8-event tunnel sample from `10.5.5.5` to `exfil-ns.example.net` —
fast-cadence, high-entropy, oversized DNS names.

## Run it

```sh
# pipe a file in
cat demos/09-stdin-pipe/events.jsonl | python -m exfilwatch scan -

# realistic: only the last N lines of a live log
tail -n 200 demos/09-stdin-pipe/events.jsonl | python -m exfilwatch scan - --format json
```

## Expected outcome

- `beaconing`, `long_dns`, and `entropy` findings for
  `10.5.5.5 -> exfil-ns.example.net`. Exit code **2**.
- Identical results whether read from a path or stdin.

## How to act

Drop this `scan -` into a cron or a log-shipping sidecar to triage streams in
near-real-time; gate alerting on the JSON `finding_count`.
