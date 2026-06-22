# Demo 10 - Calibrating Thresholds (avoiding false positives)

Not everything with entropy is malicious. Hashed-asset CDNs, cache-busting
URLs, and signed tokens all look "random". This demo shows how EXFILWATCH's
defaults stay quiet on a legitimate CDN, and what happens if you tune the
entropy threshold too aggressively.

## The log: `events.jsonl`

15 HTTPS requests from `10.40.0.8` to `static.legit-cdn.example.com`, each with
a short hashed asset folder (`/a1b2c3d4e5/asset.js`). Timing is irregular
(human page loads), and the labels are moderate-entropy — like a real CDN.

## Run it

```sh
# Defaults: correctly silent (this is benign)
python -m exfilwatch scan demos/10-tuning-fp/events.jsonl
echo "exit: $?"   # -> 0, clean

# Over-eager tuning: lowering the threshold manufactures a false positive
python -m exfilwatch scan demos/10-tuning-fp/events.jsonl --entropy-threshold 2.8
echo "exit: $?"   # -> 2, a low-severity FP on a legit CDN
```

## Expected outcome

- At the default `--entropy-threshold 3.5`: **no findings**, exit **0**.
- At `2.8`: a single **low**-severity `entropy` finding on the legit CDN.

## How to act

Treat this as a calibration guide: leave the entropy threshold at or above the
default unless you have a specific tunneling sample that demands lowering it,
and pair entropy with a second signal (beaconing / long_dns) before escalating.
Allow-list known hashed-asset CDNs in your pipeline filter.
