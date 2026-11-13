#!/usr/bin/env node
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import { EventError, parseEvents } from "./engine.js";
import { labMarkdown } from "./report.js";
import { parseRules } from "./sigma.js";
import { parseTarget, runLab } from "./lab.js";

const USAGE = `sigma-lab

  sigma-lab test <rules.yml|dir> --events events.jsonl [--target techniques.txt] [--min-precision N] [--min-recall N]

Rules: Sigma YAML, several per file separated by ---, or a directory of .yml/.yaml files.
Events: JSON Lines or a JSON array. Add "_expect": ["rule-id"] to label an event.
Exit codes: 0 ok, 1 gate failed or rule errors, 2 bad input.`;

const opt = (a: string[], n: string): string | undefined => { const i = a.indexOf(n); return i >= 0 ? a[i + 1] : undefined; };

function loadRules(p: string): string {
  if (statSync(p).isDirectory()) return readdirSync(p).filter((f) => /\.ya?ml$/.test(f)).sort().map((f) => readFileSync(path.join(p, f), "utf8")).join("\n---\n");
  return readFileSync(p, "utf8");
}

function main(argv: string[]): number {
  const [cmd, rulesPath, ...rest] = argv;
  const eventsPath = opt(rest, "--events");
  if (cmd !== "test" || !rulesPath || !eventsPath) { console.error(USAGE); return 2; }
  try {
    const { rules, errors } = parseRules(loadRules(rulesPath));
    const { events, expects } = parseEvents(readFileSync(eventsPath, "utf8"));
    const tp = opt(rest, "--target");
    const res = runLab(rules, events, expects, tp ? parseTarget(readFileSync(tp, "utf8")) : []);
    process.stdout.write(labMarkdown(res, errors));
    let fail = errors.length > 0 || res.results.some((r) => r.problems.length > 0);
    const mp = opt(rest, "--min-precision"), mr = opt(rest, "--min-recall");
    for (const r of res.results) {
      if (mp !== undefined && r.precision !== null && r.precision < Number(mp)) fail = true;
      if (mr !== undefined && r.recall !== null && r.recall < Number(mr)) fail = true;
    }
    return fail ? 1 : 0;
  } catch (e) {
    if (e instanceof EventError) { console.error(`error: ${e.message}`); return 2; }
    if ((e as NodeJS.ErrnoException).code === "ENOENT") { console.error(`error: cannot read ${(e as NodeJS.ErrnoException).path}`); return 2; }
    throw e;
  }
}

process.exitCode = main(process.argv.slice(2));
