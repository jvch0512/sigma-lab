import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { techniqueOfTag, tacticOfTag } from "../src/attack.js";
import { EventError, flatten, matches, parseEvents, validateRule } from "../src/engine.js";
import { coverage, parseTarget, runLab } from "../src/lab.js";
import { labMarkdown } from "../src/report.js";
import { RuleError, parseCondition, parseRule, parseRules } from "../src/sigma.js";
import { YamlError, parseYaml } from "../src/yaml.js";

const ex = (n: string): string => readFileSync(new URL(`../../examples/${n}`, import.meta.url), "utf8");
const rule = (y: string) => parseRule(parseYaml(y));
const ev = (o: Record<string, unknown>) => flatten(o);

test("yaml: nested maps, lists, quotes, comments, flow lists, block scalars", () => {
  const v = parseYaml(`a: 1 # c\nb:\n  - x\n  - 'it''s'\n  - "q\\"uote"\nc: [1, two, 'three, four']\nd: |\n  l1\n  l2\ne:\n  f: true\n  g: ~\nh: https://x.test/a#frag\n`) as Record<string, unknown>;
  assert.deepEqual(v, { a: 1, b: ["x", "it's", 'q"uote'], c: [1, "two", "three, four"], d: "l1\nl2", e: { f: true, g: null }, h: "https://x.test/a#frag" });
});

test("yaml: list of maps and sequences at the parent indent", () => {
  const v = parseYaml(`sel:\n- Image: a\n  User: b\n- Image: c\nlist:\n- 1\n- 2\n`) as Record<string, unknown>;
  assert.deepEqual(v, { sel: [{ Image: "a", User: "b" }, { Image: "c" }], list: [1, 2] });
});

test("yaml: rejects tabs, duplicate keys, anchors and flow maps with a line number", () => {
  assert.throws(() => parseYaml("a:\n\tb: 1"), /line 2.*tabs/);
  assert.throws(() => parseYaml("a: 1\na: 2"), /duplicate key/);
  assert.throws(() => parseYaml("a: &x 1"), /anchors/);
  assert.throws(() => parseYaml("a: {b: 1}"), /flow mappings/);
  assert.throws(() => parseYaml("a: [1, 2"), YamlError);
  assert.throws(() => parseYaml("a: 'open"), /unterminated/);
});

test("conditions: precedence, parentheses, not, of-patterns", () => {
  assert.deepEqual(parseCondition("a or b and not c"), { op: "or", a: { op: "ref", name: "a" }, b: { op: "and", a: { op: "ref", name: "b" }, b: { op: "not", a: { op: "ref", name: "c" } } } });
  assert.equal(parseCondition("(a or b) and c").op, "and");
  assert.deepEqual(parseCondition("1 of sel_*"), { op: "of", quant: "1", pattern: "sel_*" });
  assert.deepEqual(parseCondition("all of them"), { op: "of", quant: "all", pattern: "them" });
  assert.throws(() => parseCondition("a and"), RuleError);
  assert.throws(() => parseCondition("(a"), /missing/);
  assert.throws(() => parseCondition("a | count() > 5"), /aggregation/);
});

const R = `title: T\ndetection:\n  sel:\n    Image|endswith: '\\cmd.exe'\n    CommandLine|contains|all:\n      - /c\n      - whoami\n  flt:\n    User: SYSTEM\n  condition: sel and not flt\nlevel: high\n`;

test("engine: modifiers are case-insensitive and fields are AND-ed", () => {
  const r = rule(R);
  assert.equal(matches(r, ev({ Image: "C:\\Windows\\System32\\CMD.EXE", CommandLine: "cmd /C WHOAMI", User: "bob" })), true);
  assert.equal(matches(r, ev({ Image: "C:\\Windows\\System32\\cmd.exe", CommandLine: "cmd /c dir", User: "bob" })), false);
  assert.equal(matches(r, ev({ Image: "C:\\cmd.exe", CommandLine: "cmd /c whoami", User: "system" })), false);
});

test("engine: lists are OR, wildcards, null, exists, numbers, nested fields", () => {
  const r = rule(`title: T\ndetection:\n  a:\n    EventID: [4624, 4625]\n    Name: 'ab*d?f'\n  b:\n    Missing: null\n  c:\n    Process.Name|exists: true\n  condition: a and b and c\n`);
  assert.equal(matches(r, ev({ EventID: 4625, Name: "ABxxxdZf", Process: { Name: "x" } })), true);
  assert.equal(matches(r, ev({ EventID: 4626, Name: "ABxxxdZf", Process: { Name: "x" } })), false);
  assert.equal(matches(r, ev({ EventID: 4624, Name: "ABxxxdZf", Missing: "set", Process: { Name: "x" } })), false);
});

test("engine: escaped wildcard is literal, regex, windash, comparison, keywords", () => {
  assert.equal(matches(rule("title: T\ndetection:\n  s:\n    F: 'a\\*b'\n  condition: s\n"), ev({ F: "a*b" })), true);
  assert.equal(matches(rule("title: T\ndetection:\n  s:\n    F: 'a\\*b'\n  condition: s\n"), ev({ F: "axb" })), false);
  assert.equal(matches(rule("title: T\ndetection:\n  s:\n    F|re: '^ab+c$'\n  condition: s\n"), ev({ F: "abbbc" })), true);
  assert.equal(matches(rule("title: T\ndetection:\n  s:\n    F|re: '(?i)^ABC$'\n  condition: s\n"), ev({ F: "abc" })), true);
  assert.equal(matches(rule("title: T\ndetection:\n  s:\n    F|contains|windash: ' -enc '\n  condition: s\n"), ev({ F: "x /enc y" })), true);
  assert.equal(matches(rule("title: T\ndetection:\n  s:\n    N|gt: 5\n  condition: s\n"), ev({ N: 7 })), true);
  assert.equal(matches(rule("title: T\ndetection:\n  kw:\n    - mimikatz\n    - sekurlsa\n  condition: kw\n"), ev({ A: "x", B: "run SEKURLSA now" })), true);
});

test("engine: 'of' quantifiers and lookup errors", () => {
  const r = rule("title: T\ndetection:\n  s_a:\n    A: 1\n  s_b:\n    B: 2\n  condition: all of s_*\n");
  assert.equal(matches(r, ev({ A: 1, B: 2 })), true);
  assert.equal(matches(r, ev({ A: 1 })), false);
  const bad = rule("title: T\ndetection:\n  s:\n    A: 1\n  condition: s and ghost\n");
  assert.match(validateRule(bad)!, /unknown selection "ghost"/);
  const none = rule("title: T\ndetection:\n  s:\n    A: 1\n  condition: 1 of zzz*\n");
  assert.match(validateRule(none)!, /matches no selection/);
});

test("engine: an invalid user regex surfaces as an error, not a crash", () => {
  const r = rule("title: T\ndetection:\n  s:\n    F|re: '('\n  condition: s\n");
  assert.throws(() => matches(r, ev({ F: "x" })), EventError);
});

test("rule parsing: lint warnings and error cases", () => {
  const r = rule("title: Loose\ndetection:\n  s:\n    C|contains: cmd\n  condition: s\n");
  assert.ok(["no level", "no ATT&CK technique tag", "no falsepositives documented", "no id", "no logsource"].every((w) => r.warnings.includes(w)));
  assert.ok(r.warnings.some((w) => /very short value/.test(w)));
  assert.throws(() => parseRule(parseYaml("detection:\n  condition: a\n")), /no title/);
  assert.throws(() => parseRule(parseYaml("title: T\ndetection:\n  s:\n    A|nonsense: 1\n  condition: s\n")), /unsupported modifier/);
  assert.throws(() => parseRule(parseYaml("title: T\ndetection:\n  s:\n    A: 1\n")), /no condition/);
});

test("parseRules splits documents and collects errors without stopping", () => {
  const { rules, errors } = parseRules("title: A\nid: a\ndetection:\n  s:\n    X: 1\n  condition: s\n---\ntitle: B\n---\ntitle: C\nid: a\ndetection:\n  s:\n    X: 1\n  condition: s\n");
  assert.equal(rules.length, 2);
  assert.ok(errors.some((e) => /rule 2/.test(e)));
  assert.ok(errors.some((e) => /duplicate rule id: a/.test(e)));
});

test("events: JSON lines, arrays, _expect and error reporting", () => {
  const a = parseEvents('{"A":1,"_expect":["x"]}\n{"A":2}\n');
  assert.equal(a.events.length, 2);
  assert.deepEqual(a.expects, [["x"], null]);
  assert.equal(parseEvents('[{"A":1}]').events.length, 1);
  assert.throws(() => parseEvents('{"A":1}\nnope'), /line 2/);
  assert.throws(() => parseEvents('{"_expect":"x"}'), /_expect/);
  assert.throws(() => parseEvents("[1]"), /must be an object/);
});

test("ATT&CK tags", () => {
  assert.equal(techniqueOfTag("attack.t1059.001"), "T1059.001");
  assert.equal(techniqueOfTag("attack.execution"), null);
  assert.equal(tacticOfTag("attack.defense-evasion"), "defense-evasion");
  assert.equal(tacticOfTag("attack.t1059"), null);
});

test("lab: the bundled sample has the planted misses, noise and lint", () => {
  const { rules, errors } = parseRules(ex("rules.yml"));
  assert.deepEqual(errors, []);
  assert.equal(rules.length, 12);
  const { events, expects } = parseEvents(ex("events.jsonl"));
  const res = runLab(rules, events, expects, parseTarget(ex("threat-profile.txt")));
  const by = Object.fromEntries(res.results.map((r) => [r.rule.id, r]));
  assert.equal(by["ps-encoded"]!.fn, 1);
  assert.equal(by["ps-encoded"]!.recall, 2 / 3);
  assert.equal(by["schtask-create"]!.fp, 1);
  assert.equal(by["schtask-create"]!.precision, 0.5);
  assert.deepEqual(by["schtask-create"]!.fpAt, [19]);
  assert.equal(by["lsass-dump"]!.precision, 1);
  assert.ok(res.results.every((r) => r.problems.length === 0));
});

test("lab: no labels means no precision or recall", () => {
  const { rules } = parseRules(ex("rules.yml"));
  const res = runLab(rules, [ev({ A: 1 })], [null]);
  assert.ok(res.results.every((r) => r.precision === null && r.recall === null));
});

test("coverage: covered, partial via sub-technique or parent, gap", () => {
  const { rules } = parseRules(ex("rules.yml"));
  const c = coverage(rules, ["T1059.001", "T1218", "T1053", "T1047", "T1059.003"]);
  const st = Object.fromEntries(c.target.map((t) => [t.id, t.state]));
  assert.deepEqual(st, { "T1059.001": "covered", T1218: "partial", T1053: "partial", T1047: "gap", "T1059.003": "gap" });
});

test("target file parsing handles comments and duplicates", () => {
  assert.deepEqual(parseTarget("T1059.001 # ps\n# T9999\nt1003.001\nT1059.001"), ["T1059.001", "T1003.001"]);
});

test("report names false positives and misses with event numbers", () => {
  const { rules, errors } = parseRules(ex("rules.yml"));
  const { events, expects } = parseEvents(ex("events.jsonl"));
  const md = labMarkdown(runLab(rules, events, expects, parseTarget(ex("threat-profile.txt"))), errors);
  assert.match(md, /Scheduled task created from the command line: unexpected hit on event 19/);
  assert.match(md, /Encoded PowerShell command line: expected but not matched on event 3/);
  assert.match(md, /9 of 14 target techniques covered, 1 partially/);
});
