# Demo 02 - Clean Baseline (no findings)

A baseline capture of an ordinary corporate workstation. Establishing what
"quiet" looks like is half the job: if EXFILWATCH stays silent on known-good
traffic, you can trust its alerts on the noisy captures.

## The log: `events.jsonl`

~60 events of normal browsing from `10.10.5.21` — DNS lookups and HTTPS GETs
to first-party hosts (`www`, `mail`, `docs`, `api`, `cdn`, `updates` under
`example.com`). Timing is irregular (human), hostnames are dictionary words,
and HTTP paths are plain (`/index.html`).

## Run it

```sh
python -m exfilwatch scan demos/02-clean/events.jsonl
echo "exit: $?"
```

## Expected outcome

- **No exfiltration indicators detected.**
- Exit code **0** (clean) — use as a CI gate's pass case.

## How to act

Nothing to do. Keep this file as a regression fixture: if a future detector
tweak starts flagging it, you have an over-eager rule to investigate.

> Authorized, defensive use only. EXFILWATCH reads logs and reports indicators;
> it performs no network activity.
