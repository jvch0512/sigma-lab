import { LabResult } from "./lab.js";
import { TECHNIQUES } from "./attack.js";

const cell = (s: string): string => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const pct = (x: number | null): string => (x === null ? "-" : `${Math.round(x * 100)}%`);

export function labMarkdown(r: LabResult, errors: string[] = []): string {
  const L = ["# Sigma lab report", "", `${r.results.length} rules against ${r.eventCount} events (${r.labelled} labelled).`, ""];
  if (errors.length) { L.push("## Parse errors", ""); for (const e of errors) L.push(`- ${e}`); L.push(""); }
  L.push("## Rules", "", "| Rule | Level | Techniques | Hits | TP | FP | FN | Precision | Recall |", "|---|---|---|---|---|---|---|---|---|");
  for (const x of r.results) L.push(`| ${cell(x.rule.title)} | ${x.rule.level} | ${x.techniques.join(", ") || "-"} | ${x.hits.length} | ${x.tp} | ${x.fp} | ${x.fn} | ${pct(x.precision)} | ${pct(x.recall)} |`);
  L.push("");
  const lint = r.results.filter((x) => x.rule.warnings.length || x.problems.length);
  if (lint.length) {
    L.push("## Lint", "");
    for (const x of lint) L.push(`- **${x.rule.title}**: ${[...x.problems, ...x.rule.warnings].join("; ")}`);
    L.push("");
  }
  const noisy = r.results.filter((x) => x.fp > 0);
  if (noisy.length) { L.push("## False positives to tune", ""); for (const x of noisy) L.push(`- ${x.rule.title}: unexpected hit on event ${x.fpAt.join(", ")}`); L.push(""); }
  const missed = r.results.filter((x) => x.fn > 0);
  if (missed.length) { L.push("## Missed detections", ""); for (const x of missed) L.push(`- ${x.rule.title}: expected but not matched on event ${x.fnAt.join(", ")}`); L.push(""); }
  L.push("## ATT&CK coverage by tactic", "");
  for (const t of r.coverage.byTactic) L.push(`- **${t.tactic}**: ${t.techniques.map((id) => `${id} ${TECHNIQUES[id]?.name ?? ""}`.trim()).join(", ")}`);
  if (r.coverage.unknownTechniques.length) L.push("", `Techniques tagged in rules but missing from the built-in table: ${r.coverage.unknownTechniques.join(", ")}.`);
  L.push("");
  if (r.coverage.target.length) {
    const c = r.coverage.target.filter((x) => x.state === "covered").length;
    const p = r.coverage.target.filter((x) => x.state === "partial").length;
    L.push("## Threat profile", "", `${c} of ${r.coverage.target.length} target techniques covered, ${p} partially.`, "", "| Technique | Name | State | Rules |", "|---|---|---|---|");
    for (const x of r.coverage.target) L.push(`| ${x.id} | ${cell(x.name)} | ${x.state} | ${x.by.join(", ") || "-"} |`);
    L.push("");
  }
  L.push("_Coverage means a rule is tagged for the technique, not that it detects every variant. Precision and recall use only the events that carry an `_expect` label._", "");
  return L.join("\n");
}
