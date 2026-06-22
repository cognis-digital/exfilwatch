package main

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	if ShannonEntropy("") != 0 {
		t.Fatal("empty string should be 0")
	}
	if ShannonEntropy("aaaaaaaa") != 0 {
		t.Fatal("uniform string should be 0")
	}
	rnd := ShannonEntropy("mfrggzdfmztwq2lknbswg43f")
	word := ShannonEntropy("newsletter")
	if rnd <= word {
		t.Fatalf("random %.3f should exceed word %.3f", rnd, word)
	}
	// known value: "ab" -> 1 bit/char
	if math.Abs(ShannonEntropy("ab")-1.0) > 1e-9 {
		t.Fatalf("ab entropy = %v, want 1.0", ShannonEntropy("ab"))
	}
}

func TestRegistrableLabels(t *testing.T) {
	got := registrableLabels("a8f3.x9q2.evil.example.com")
	want := []string{"a8f3", "x9q2", "evil"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if registrableLabels("example.com") != nil {
		t.Fatal("2-label domain should yield no registrable labels")
	}
}

func TestSeverity(t *testing.T) {
	cases := map[float64]string{0.1: "low", 0.5: "medium", 0.8: "high", 0.75: "high", 0.49: "low"}
	for score, want := range cases {
		if got := severity(score); got != want {
			t.Fatalf("severity(%v)=%s want %s", score, got, want)
		}
	}
}

func TestAnalyzeFlagsTunnel(t *testing.T) {
	events := []Event{
		{Src: "10.0.0.5", Dst: "evil-tunnel.example.net", Proto: "dns",
			Query: "mfrggzdfmztwq2lknbswg43f.aebagbaf.zw6mb44q.evil-tunnel.example.net"},
		{Src: "10.0.0.5", Dst: "evil-tunnel.example.net", Proto: "dns",
			Query: "nbswy3dpfqqho33snrscc.aebagbaf.zwy7q.evil-tunnel.example.net"},
		{Src: "10.0.0.12", Dst: "www.example.com", Proto: "dns", Query: "www.example.com"},
	}
	fs := analyze(events)
	if len(fs) == 0 {
		t.Fatal("expected findings for the tunnel")
	}
	found := false
	for _, f := range fs {
		if f.Dst == "evil-tunnel.example.net" {
			found = true
		}
		if f.Dst == "www.example.com" {
			t.Fatal("benign host should not be flagged")
		}
	}
	if !found {
		t.Fatal("tunnel host not flagged")
	}
}

func TestAnalyzeClean(t *testing.T) {
	events := []Event{
		{Src: "10.0.0.12", Dst: "www.example.com", Proto: "dns", Query: "www.example.com"},
		{Src: "10.0.0.12", Dst: "cdn.example.org", Proto: "dns", Query: "cdn.example.org"},
	}
	if fs := analyze(events); len(fs) != 0 {
		t.Fatalf("benign log should be clean, got %v", fs)
	}
}

func TestAnalyzeLongDNS(t *testing.T) {
	long := "verylonglabelthatissmuggledatapayloadbase32encodedstuff." +
		"morelonglabelhere.tunnel.example.net"
	events := []Event{{Src: "a", Dst: "tunnel.example.net", Proto: "dns", Query: long}}
	fs := analyze(events)
	has := false
	for _, f := range fs {
		if f.Detector == "long_dns" {
			has = true
		}
	}
	if !has {
		t.Fatal("expected long_dns finding")
	}
}
