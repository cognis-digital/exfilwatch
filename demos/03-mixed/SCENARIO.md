# Demo 03 - One Beacon Hidden in Browsing Noise

The realistic case: a single compromised host is beaconing to a C2, but it is
*also* doing a lot of legitimate browsing. The signal is buried in noise.

## The log: `events.jsonl`

~52 events from `10.10.5.30`. Most are ordinary HTTPS page loads to first-party
hosts at irregular intervals. Interleaved among them are 12 callbacks to
`telemetry-sync.example.org` exactly every ~300 s (5-minute beacon, sub-second
jitter).

## Run it

```sh
python -m exfilwatch scan demos/03-mixed/events.jsonl
```

## Expected outcome

- A **high**-severity `beaconing` finding for
  `10.10.5.30 -> telemetry-sync.example.org` (~300 s, <1% jitter).
- Exit code **2**.
- The benign browsing to `example.com` hosts is **not** flagged.

## How to act

Pivot on `telemetry-sync.example.org`: confirm it is not an approved telemetry
endpoint, block it at egress, and triage `10.10.5.30` for the implant driving
the 5-minute cadence.
