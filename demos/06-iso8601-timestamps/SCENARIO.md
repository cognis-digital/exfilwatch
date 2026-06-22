# Demo 06 - SIEM Export with ISO-8601 Timestamps

Not every log uses epoch seconds. This capture comes straight out of a SIEM
that emits RFC-3339 / ISO-8601 timestamps (`2026-06-18T14:00:00Z`).
EXFILWATCH parses both transparently.

## The log: `events.jsonl`

50 events from `10.0.3.77` to `beacon-host.example.com` with **string**
timestamps: 40 high-entropy DNS queries plus a regular 45 s HTTP beacon.

## Run it

```sh
python -m exfilwatch scan demos/06-iso8601-timestamps/events.jsonl
```

## Expected outcome

- `entropy` and `long_dns` findings on the DNS traffic to
  `beacon-host.example.com`. Exit code **2**.
- Confirms ISO-8601 timestamps parse the same as epoch seconds.

## How to act

This demo doubles as an ingestion test: if your SIEM export parses cleanly here,
you can pipe it straight into `--format json` / `--format sarif` for automation.
