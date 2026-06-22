# Demo 05 - HTTP C2 Heartbeat with Jitter

Modern implants add small random jitter to their call-home interval to dodge
naive "exactly every N seconds" rules. EXFILWATCH scores on the coefficient of
variation of intervals, so a low-jitter heartbeat still stands out.

## The log: `events.jsonl`

20 HTTPS requests from `192.168.8.44` to
`status.update-cdn.example.io/heartbeat`, spaced ~600 s apart with a few
seconds of jitter and a tiny varying body size.

## Run it

```sh
python -m exfilwatch scan demos/05-http-beacon-jitter/events.jsonl
```

To prove the jitter tolerance, tighten the gate and watch it still fire:

```sh
python -m exfilwatch scan demos/05-http-beacon-jitter/events.jsonl --beacon-max-jitter 0.05
```

## Expected outcome

- A **high**-severity `beaconing` finding (~600 s, well under 1% jitter) over
  20 callbacks. Exit code **2**.

## How to act

A 10-minute heartbeat to a "status CDN" that is not in your asset inventory is
a strong C2 indicator. Block the host and hunt for the process on `192.168.8.44`.
