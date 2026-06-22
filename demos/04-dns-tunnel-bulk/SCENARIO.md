# Demo 04 - Sustained DNS Tunnel (bulk exfiltration)

A classic DNS-tunneling pattern (iodine / dnscat2 style): a single internal
host pushes a steady stream of encoded queries to one attacker-controlled
nameserver, smuggling data out one label at a time.

## The log: `events.jsonl`

60 DNS queries from `172.16.40.13` to `tunnel.dataexfil.example.net`, a couple
of seconds apart. Each query carries two base32-looking labels (a ~20-char data
chunk plus a short sequence tag) prepended to the C2 domain.

## Run it

```sh
python -m exfilwatch scan demos/04-dns-tunnel-bulk/events.jsonl
python -m exfilwatch scan demos/04-dns-tunnel-bulk/events.jsonl --format json | jq '.findings[].detector'
```

## Expected outcome

- A `long_dns` finding (oversized query names) AND an `entropy` finding
  (high-entropy labels) for `172.16.40.13 -> tunnel.dataexfil.example.net`.
- Exit code **2**.

## How to act

Two detectors agreeing on the same destination is high confidence. Sinkhole or
block `*.tunnel.dataexfil.example.net`, capture full PCAP for the resolver, and
isolate `172.16.40.13`.
