# Demo 08 - Botnet Fan-out (many hosts, one C2)

When several internal hosts all beacon to the *same* external destination on the
same cadence, you are likely looking at a botnet or a worm with shared C2.
EXFILWATCH groups per `src -> dst`, so each infected host gets its own finding
while the shared destination makes the pattern obvious.

## The log: `events.jsonl`

Four hosts (`10.30.2.11`-`.14`) each send 15 callbacks to
`sync.shadow-update.example.net` every ~120 s (staggered start phase), plus
benign browsing from one of them as a control.

## Run it

```sh
python -m exfilwatch scan demos/08-multi-host-fanout/events.jsonl
python -m exfilwatch scan demos/08-multi-host-fanout/events.jsonl --format json \
  | jq -r '.findings[] | select(.detector=="beaconing") | .src'
```

## Expected outcome

- Four **high**-severity `beaconing` findings — one per infected host — all
  pointing at `sync.shadow-update.example.net`. Exit code **2**.
- The benign `www.example.com` browsing is not flagged.

## How to act

One destination, four victims, identical cadence = coordinated C2. Block the
domain network-wide and sweep all four hosts; the shared cadence is your IOC.
