// Go port of the EXFILWATCH core check — passive, offline, zero deps.
//
// Reads newline-delimited JSON log events (ts, src, dst, proto, query) from a
// file argument or stdin and flags DNS exfiltration indicators:
//   * high Shannon entropy in DNS labels (encoded payload)
//   * oversized DNS query names (tunnelling)
// Output shape matches the Python reference: {"tool","findings":[...],"score"}.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
)

type Event struct {
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	Query string `json:"query"`
}

type Finding struct {
	Detector string  `json:"detector"`
	Severity string  `json:"severity"`
	Src      string  `json:"src"`
	Dst      string  `json:"dst"`
	Score    float64 `json:"score"`
	Summary  string  `json:"summary"`
}

// ShannonEntropy returns bits/char; 0 for empty.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, c := range s {
		counts[c]++
	}
	n := float64(len([]rune(s)))
	ent := 0.0
	for _, c := range counts {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// registrableLabels drops the assumed 2-label registrable suffix.
func registrableLabels(domain string) []string {
	var parts []string
	for _, p := range strings.Split(domain, ".") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) <= 2 {
		return nil
	}
	return parts[:len(parts)-2]
}

func severity(score float64) string {
	switch {
	case score >= 0.75:
		return "high"
	case score >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

const (
	entropyThreshold = 3.5
	minLen           = 8
	maxNameLen       = 52
)

func analyze(events []Event) []Finding {
	type stat struct {
		hi, total int
		peak      float64
	}
	groups := map[string]*stat{}
	longest := map[string]int{}
	pairSrc := map[string]string{}
	pairDst := map[string]string{}

	for _, ev := range events {
		if ev.Proto != "dns" {
			continue
		}
		name := ev.Query
		if name == "" {
			name = ev.Dst
		}
		key := ev.Src + "\x00" + ev.Dst
		pairSrc[key] = ev.Src
		pairDst[key] = ev.Dst
		for _, lbl := range registrableLabels(name) {
			if len([]rune(lbl)) < minLen {
				continue
			}
			s := groups[key]
			if s == nil {
				s = &stat{}
				groups[key] = s
			}
			s.total++
			e := ShannonEntropy(lbl)
			if e >= entropyThreshold {
				s.hi++
				if e > s.peak {
					s.peak = e
				}
			}
		}
		if len(name) > longest[key] {
			longest[key] = len(name)
		}
	}

	var fs []Finding
	for key, s := range groups {
		if s.hi == 0 {
			continue
		}
		frac := float64(s.hi) / float64(s.total)
		peakFactor := math.Min(1.0, (s.peak-entropyThreshold)/1.5)
		score := math.Min(1.0, 0.5*frac+0.5*peakFactor)
		score = math.Round(score*1000) / 1000
		fs = append(fs, Finding{"entropy", severity(score), pairSrc[key], pairDst[key], score,
			fmt.Sprintf("%d/%d labels exceed entropy %.1f (peak %.2f) toward %s",
				s.hi, s.total, entropyThreshold, s.peak, pairDst[key])})
	}
	for key, nl := range longest {
		if nl <= maxNameLen {
			continue
		}
		over := math.Min(1.0, float64(nl-maxNameLen)/float64(maxNameLen))
		score := math.Round((0.4+0.6*over)*1000) / 1000
		fs = append(fs, Finding{"long_dns", severity(score), pairSrc[key], pairDst[key], score,
			fmt.Sprintf("oversized DNS query (%d chars) to %s", nl, pairDst[key])})
	}
	return fs
}

func readEvents(r *bufio.Scanner) []Event {
	var events []Event
	r.Buffer(make([]byte, 1024*1024), 1024*1024)
	for r.Scan() {
		line := strings.TrimSpace(r.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		ev.Proto = strings.ToLower(ev.Proto)
		events = append(events, ev)
	}
	return events
}

func main() {
	var sc *bufio.Scanner
	if len(os.Args) > 1 && os.Args[1] != "-" {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer f.Close()
		sc = bufio.NewScanner(f)
	} else {
		sc = bufio.NewScanner(os.Stdin)
	}
	fs := analyze(readEvents(sc))
	if fs == nil {
		fs = []Finding{}
	}
	out, _ := json.MarshalIndent(map[string]any{
		"tool": "exfilwatch", "findings": fs, "score": len(fs),
	}, "", "  ")
	fmt.Println(string(out))
	if len(fs) > 0 {
		os.Exit(2)
	}
}
