# Demo 11 — C2 attribution via threat-intel enrichment

Behavioural detection finds a regular HTTP beacon from `10.0.0.5` and a
high-entropy DNS tunnel from `10.0.0.7`. The `--enrich` flag then cross-
references the destinations against the abuse.ch **Feodo Tracker** C2 IP
blocklist and **ThreatFox** IOC feed and attributes them:

* `185.244.25.231` -> known **Emotet** C2 (Feodo Tracker)
* `evil-exfil.example.com` -> **Cobalt Strike** IOC (ThreatFox)

Both are bumped to **high** severity with the malware family attached to the
finding evidence.

## Run it (air-gapped, from the committed fixture cache)

```sh
export COGNIS_FEEDS_CACHE="$(git rev-parse --show-toplevel)/tests/fixtures/feeds-cache"
python -m exfilwatch scan demos/11-c2-attribution/events.jsonl --enrich --offline
```

## Run it live (refreshes the feeds from abuse.ch)

```sh
python -m exfilwatch feeds update feodo-c2 threatfox
python -m exfilwatch scan demos/11-c2-attribution/events.jsonl --enrich
```
