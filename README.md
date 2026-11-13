# sigma-lab

Detection-as-code lab for Sigma rules. Write rules, label a small set of events, and see precision and recall per rule, lint warnings and MITRE ATT&CK coverage against your own threat profile. Zero runtime dependencies, runs as a CLI and as a browser tool.

Live demo: https://jvch0512.github.io/sigma-lab/ (runs in the tab, nothing is uploaded)

## Why

A detection that nobody tested is a hope. sigma-lab closes the loop in seconds: each event can carry `_expect: ["rule-id"]`, so the tool knows which hits are true positives, which are false positives and which detections were missed. The coverage view then answers the question a CISO asks: of the techniques in our threat profile, which are covered, partly covered or open.

## Quick start

```bash
npm install
npm test
node dist/src/cli.js test examples/rules.yml --events examples/events.jsonl --target examples/threat-profile.txt
npm start   # UI on http://127.0.0.1:8787
```

Gates for CI:

```bash
node dist/src/cli.js test rules.yml --events events.jsonl --min-precision 0.9 --min-recall 1   # exit 1 when below
```

## Supported Sigma subset

- Multi-document YAML (rules separated by `---`), own small YAML parser, no dependencies.
- Selections as maps or lists, keyword lists, `and` / `or` / `not`, parentheses, `1 of`, `all of`, wildcards (`selection*`, `them`).
- Field modifiers: `contains`, `startswith`, `endswith`, `all`, `re`, `windash`, `exists`, `lt`, `gt`.
- ATT&CK tags (`attack.t1059.001`, `attack.execution`) mapped to a built-in technique table.
- Not supported: aggregations (`count`, `near`), correlation rules. They are reported, not silently ignored.

## Event labels

```json
{"EventID": 4688, "CommandLine": "powershell -enc ...", "_expect": ["ps-encoded"]}
```

Events without `_expect` count as expected-clean, so any hit on them is a false positive.

## Outputs

Markdown report with per-rule precision and recall, lint warnings, tuning hints (which event fired unexpectedly or was missed) and the coverage table by tactic. See `docs/sample-report.md`.

## Limits

The coverage table is only as good as your tags and your threat profile. The technique table is a curated subset of ATT&CK, not the full matrix. Rule matching follows common Sigma semantics but is not a replacement for a production backend converter such as sigma-cli.

## License

MIT
