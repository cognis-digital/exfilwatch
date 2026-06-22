# Demo 07 - Base64 Payloads in HTTP URL Paths

Data does not only leave over DNS. This host sends base64url blobs encoded
directly into the URL path of an "asset" endpoint — staging exfiltration through
what looks like a CDN upload path.

## The log: `events.jsonl`

25 HTTPS requests from `10.20.1.9` to `assets.metrics-collect.example.io`, each
with a unique ~32-char base64url segment after `/upload/`.

## Run it

```sh
python -m exfilwatch scan demos/07-http-path-exfil/events.jsonl
```

## Expected outcome

- A **high**-severity `entropy` finding: every path segment exceeds the entropy
  threshold (peak ~4.7 bits/char). Exit code **2**.
- Note: the hostname alone does not trigger entropy — only the encoded path
  does. EXFILWATCH analyses the path/query, not the FQDN, for HTTP.

## How to act

Block the destination and capture the request bodies. High-entropy URL paths to
a single host are a reliable staging-exfil indicator.
