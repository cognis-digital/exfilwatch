// Node built-in test runner: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  shannonEntropy,
  registrableLabels,
  severity,
  analyze,
  parseEvents,
  scan,
} from "./index.js";

test("shannon entropy empty and uniform", () => {
  assert.equal(shannonEntropy(""), 0);
  assert.equal(shannonEntropy("aaaaaaaa"), 0);
  assert.ok(Math.abs(shannonEntropy("ab") - 1.0) < 1e-9);
});

test("shannon entropy random exceeds word", () => {
  assert.ok(shannonEntropy("mfrggzdfmztwq2lknbswg43f") > shannonEntropy("newsletter"));
});

test("registrable labels strip 2-label suffix", () => {
  assert.deepEqual(registrableLabels("a8f3.x9q2.evil.example.com"), ["a8f3", "x9q2", "evil"]);
  assert.deepEqual(registrableLabels("example.com"), []);
});

test("severity bands", () => {
  assert.equal(severity(0.8), "high");
  assert.equal(severity(0.5), "medium");
  assert.equal(severity(0.1), "low");
});

test("analyze flags tunnel not benign", () => {
  const events = [
    {
      src: "10.0.0.5",
      dst: "evil-tunnel.example.net",
      proto: "dns",
      query: "mfrggzdfmztwq2lknbswg43f.aebagbaf.zw6mb44q.evil-tunnel.example.net",
    },
    { src: "10.0.0.12", dst: "www.example.com", proto: "dns", query: "www.example.com" },
  ];
  const fs = analyze(events);
  assert.ok(fs.some((f) => f.dst === "evil-tunnel.example.net"));
  assert.ok(!fs.some((f) => f.dst === "www.example.com"));
});

test("analyze clean log is empty", () => {
  const events = [{ src: "a", dst: "www.example.com", proto: "dns", query: "www.example.com" }];
  assert.equal(analyze(events).length, 0);
});

test("parseEvents skips comments, blanks, malformed", () => {
  const text = '# c\n\n{"ts":1,"src":"a","dst":"b","proto":"dns"}\n{bad json}\n';
  assert.equal(parseEvents(text).length, 1);
});

test("scan output shape", () => {
  const text = '{"ts":1,"src":"a","dst":"b.c.d.example.net","proto":"dns","query":"mfrggzdfmztwq2lknbswg43f.x.y.b.c.d.example.net"}\n';
  const r = scan(text);
  assert.equal(r.tool, "exfilwatch");
  assert.ok(Array.isArray(r.findings));
  assert.equal(r.score, r.findings.length);
});
