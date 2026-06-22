// Rust port of the EXFILWATCH core check — passive, offline, std-only.
//
// Reads newline-delimited JSON log events (ts, src, dst, proto, query) from a
// file argument or stdin and flags DNS exfiltration indicators (high Shannon
// entropy in DNS labels, oversized DNS names). std-only: a minimal string
// field extractor avoids any external JSON dependency.
use std::collections::HashMap;
use std::io::{self, Read};
use std::{env, fs};

const ENTROPY_THRESHOLD: f64 = 3.5;
const MIN_LEN: usize = 8;
const MAX_NAME_LEN: usize = 52;

/// Shannon entropy in bits/char; 0.0 for empty.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut n = 0usize;
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        n += 1;
    }
    let nf = n as f64;
    let mut ent = 0.0;
    for &c in counts.values() {
        let p = c as f64 / nf;
        ent -= p * p.log2();
    }
    ent
}

/// Drop the assumed 2-label registrable suffix.
pub fn registrable_labels(domain: &str) -> Vec<&str> {
    let parts: Vec<&str> = domain.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 2 {
        return vec![];
    }
    parts[..parts.len() - 2].to_vec()
}

pub fn severity(score: f64) -> &'static str {
    if score >= 0.75 {
        "high"
    } else if score >= 0.5 {
        "medium"
    } else {
        "low"
    }
}

/// Extract a JSON string field value (handles simple unescaped values).
fn json_str(line: &str, key: &str) -> String {
    let pat = format!("\"{}\"", key);
    if let Some(i) = line.find(&pat) {
        let rest = &line[i + pat.len()..];
        if let Some(c) = rest.find(':') {
            let mut after = rest[c + 1..].trim_start();
            if let Some(stripped) = after.strip_prefix('"') {
                after = stripped;
                if let Some(end) = after.find('"') {
                    return after[..end].to_string();
                }
            }
        }
    }
    String::new()
}

#[derive(Default, Clone)]
struct Event {
    src: String,
    dst: String,
    proto: String,
    query: String,
}

pub struct Finding {
    pub detector: String,
    pub severity: String,
    pub src: String,
    pub dst: String,
    pub score: f64,
    pub summary: String,
}

fn round3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn analyze(events: &[Event]) -> Vec<Finding> {
    struct Stat {
        hi: usize,
        total: usize,
        peak: f64,
        src: String,
        dst: String,
    }
    let mut groups: HashMap<String, Stat> = HashMap::new();
    let mut longest: HashMap<String, (usize, String, String)> = HashMap::new();

    for ev in events {
        if ev.proto != "dns" {
            continue;
        }
        let name = if !ev.query.is_empty() { &ev.query } else { &ev.dst };
        let key = format!("{}\u{0}{}", ev.src, ev.dst);
        for lbl in registrable_labels(name) {
            if lbl.chars().count() < MIN_LEN {
                continue;
            }
            let s = groups.entry(key.clone()).or_insert(Stat {
                hi: 0,
                total: 0,
                peak: 0.0,
                src: ev.src.clone(),
                dst: ev.dst.clone(),
            });
            s.total += 1;
            let e = shannon_entropy(lbl);
            if e >= ENTROPY_THRESHOLD {
                s.hi += 1;
                if e > s.peak {
                    s.peak = e;
                }
            }
        }
        let entry = longest
            .entry(key.clone())
            .or_insert((0, ev.src.clone(), ev.dst.clone()));
        if name.len() > entry.0 {
            entry.0 = name.len();
        }
    }

    let mut fs = Vec::new();
    for s in groups.values() {
        if s.hi == 0 {
            continue;
        }
        let frac = s.hi as f64 / s.total as f64;
        let peak_factor = (1.0_f64).min((s.peak - ENTROPY_THRESHOLD) / 1.5);
        let score = round3((0.5 * frac + 0.5 * peak_factor).min(1.0));
        fs.push(Finding {
            detector: "entropy".into(),
            severity: severity(score).into(),
            src: s.src.clone(),
            dst: s.dst.clone(),
            score,
            summary: format!(
                "{}/{} labels exceed entropy {} (peak {:.2}) toward {}",
                s.hi, s.total, ENTROPY_THRESHOLD, s.peak, s.dst
            ),
        });
    }
    for (nl, src, dst) in longest.values() {
        if *nl <= MAX_NAME_LEN {
            continue;
        }
        let over = (1.0_f64).min((*nl - MAX_NAME_LEN) as f64 / MAX_NAME_LEN as f64);
        let score = round3(0.4 + 0.6 * over);
        fs.push(Finding {
            detector: "long_dns".into(),
            severity: severity(score).into(),
            src: src.clone(),
            dst: dst.clone(),
            score,
            summary: format!("oversized DNS query ({} chars) to {}", nl, dst),
        });
    }
    fs
}

fn parse_events(text: &str) -> Vec<Event> {
    let mut events = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        events.push(Event {
            src: json_str(line, "src"),
            dst: json_str(line, "dst"),
            proto: json_str(line, "proto").to_lowercase(),
            query: json_str(line, "query"),
        });
    }
    events
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let text = if args.len() > 1 && args[1] != "-" {
        fs::read_to_string(&args[1]).unwrap_or_else(|e| {
            eprintln!("error: {}", e);
            std::process::exit(1);
        })
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).ok();
        buf
    };
    let fs_out = analyze(&parse_events(&text));
    let items: Vec<String> = fs_out
        .iter()
        .map(|f| {
            format!(
                "    {{\"detector\":\"{}\",\"severity\":\"{}\",\"src\":\"{}\",\"dst\":\"{}\",\"score\":{},\"summary\":\"{}\"}}",
                f.detector,
                f.severity,
                json_escape(&f.src),
                json_escape(&f.dst),
                f.score,
                json_escape(&f.summary)
            )
        })
        .collect();
    println!(
        "{{\n  \"tool\": \"exfilwatch\",\n  \"findings\": [\n{}\n  ],\n  \"score\": {}\n}}",
        items.join(",\n"),
        fs_out.len()
    );
    if !fs_out.is_empty() {
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_empty_and_uniform() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
        assert!((shannon_entropy("ab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn entropy_random_exceeds_word() {
        assert!(shannon_entropy("mfrggzdfmztwq2lknbswg43f") > shannon_entropy("newsletter"));
    }

    #[test]
    fn registrable_labels_strip_suffix() {
        assert_eq!(
            registrable_labels("a8f3.x9q2.evil.example.com"),
            vec!["a8f3", "x9q2", "evil"]
        );
        assert!(registrable_labels("example.com").is_empty());
    }

    #[test]
    fn severity_bands() {
        assert_eq!(severity(0.8), "high");
        assert_eq!(severity(0.5), "medium");
        assert_eq!(severity(0.1), "low");
    }

    #[test]
    fn analyze_flags_tunnel_not_benign() {
        let events = vec![
            Event {
                src: "10.0.0.5".into(),
                dst: "evil-tunnel.example.net".into(),
                proto: "dns".into(),
                query: "mfrggzdfmztwq2lknbswg43f.aebagbaf.zw6mb44q.evil-tunnel.example.net".into(),
            },
            Event {
                src: "10.0.0.12".into(),
                dst: "www.example.com".into(),
                proto: "dns".into(),
                query: "www.example.com".into(),
            },
        ];
        let fs = analyze(&events);
        assert!(fs.iter().any(|f| f.dst == "evil-tunnel.example.net"));
        assert!(!fs.iter().any(|f| f.dst == "www.example.com"));
    }

    #[test]
    fn analyze_clean_log() {
        let events = vec![Event {
            src: "a".into(),
            dst: "www.example.com".into(),
            proto: "dns".into(),
            query: "www.example.com".into(),
        }];
        assert!(analyze(&events).is_empty());
    }

    #[test]
    fn json_str_extracts() {
        let line = r#"{"ts":1,"src":"10.0.0.5","dst":"x.example.net","proto":"dns"}"#;
        assert_eq!(json_str(line, "src"), "10.0.0.5");
        assert_eq!(json_str(line, "proto"), "dns");
        assert_eq!(json_str(line, "missing"), "");
    }
}
