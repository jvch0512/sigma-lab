node dist/src/cli.js test examples/rules.yml --events examples/events.jsonl --target examples/threat-profile.txt > /tmp/lab.md
diff /tmp/lab.md docs/sample-report.md
test "$(node dist/src/cli.js test examples/rules.yml --events examples/events.jsonl --min-recall 1 >/dev/null; echo $?)" = "1"
