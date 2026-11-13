import { Event, matches, validateRule } from "./engine.js";
import { Rule } from "./sigma.js";
import { TECHNIQUES, TACTICS, Tactic, parentOf, tacticOfTag, techniqueOfTag } from "./attack.js";

export interface RuleResult {
  rule: Rule;
  techniques: string[];
  hits: number[];
  tp: number;
  fp: number;
  fn: number;
  /** 1-based event numbers of unexpected hits and of missed expectations */
  fpAt: number[];
  fnAt: number[];
  /** null when no event carries an expectation */
  precision: number | null;
  recall: number | null;
  problems: string[];
}

export interface Coverage {
  covered: Record<string, string[]>;
  byTactic: { tactic: Tactic; techniques: string[] }[];
  unknownTechniques: string[];
  target: { id: string; name: string; state: "covered" | "partial" | "gap"; by: string[] }[];
}

export interface LabResult { results: RuleResult[]; coverage: Coverage; eventCount: number; labelled: number }

export function ruleTechniques(r: Rule): string[] {
  return [...new Set(r.tags.map(techniqueOfTag).filter((x): x is string => x !== null))].sort();
}

export function runLab(rules: Rule[], events: Event[], expects: (string[] | null)[], target: string[] = []): LabResult {
  const results: RuleResult[] = rules.map((rule) => {
    const problems: string[] = [];
    const bad = validateRule(rule);
    if (bad) problems.push(bad);
    const hits: number[] = [];
    let tp = 0, fp = 0, fn = 0;
    const fpAt: number[] = [], fnAt: number[] = [];
    if (!bad) events.forEach((ev, i) => {
      const hit = matches(rule, ev);
      if (hit) hits.push(i);
      const ex = expects[i];
      if (ex) {
        const should = ex.includes(rule.id);
        if (hit && should) tp++; else if (hit && !should) { fp++; fpAt.push(i + 1); } else if (!hit && should) { fn++; fnAt.push(i + 1); }
      }
    });
    const labelled = expects.some((e) => e !== null);
    return { rule, techniques: ruleTechniques(rule), hits, tp, fp, fn, fpAt, fnAt, problems,
      precision: labelled && tp + fp > 0 ? tp / (tp + fp) : null,
      recall: labelled && tp + fn > 0 ? tp / (tp + fn) : null };
  });
  return { results, coverage: coverage(rules, target), eventCount: events.length, labelled: expects.filter((e) => e !== null).length };
}

export function parseTarget(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    for (const m of line.replace(/#.*/, "").matchAll(/\bT\d{4}(?:\.\d{3})?\b/gi)) out.push(m[0].toUpperCase());
  }
  return [...new Set(out)];
}

export function coverage(rules: Rule[], target: string[]): Coverage {
  const covered: Record<string, string[]> = {};
  const unknown = new Set<string>();
  const tacticTags = new Map<Tactic, Set<string>>();
  for (const r of rules) {
    for (const t of ruleTechniques(r)) {
      (covered[t] ??= []).push(r.id);
      if (!(t in TECHNIQUES)) unknown.add(t);
    }
    for (const tag of r.tags) { const tc = tacticOfTag(tag); if (tc) { const s = tacticTags.get(tc) ?? new Set(); s.add(r.id); tacticTags.set(tc, s); } }
  }
  const byTactic = TACTICS.map((tactic) => ({
    tactic,
    techniques: Object.keys(covered).filter((t) => (TECHNIQUES[t]?.tactics ?? []).includes(tactic)).sort(),
  })).filter((x) => x.techniques.length > 0);
  const tgt = target.map((id) => {
    const direct = covered[id] ?? [];
    const viaSub = Object.keys(covered).filter((k) => k.startsWith(`${id}.`)).flatMap((k) => covered[k]!);
    const viaParent = id.includes(".") ? covered[parentOf(id)] ?? [] : [];
    const state: "covered" | "partial" | "gap" = direct.length ? "covered" : viaSub.length || viaParent.length ? "partial" : "gap";
    return { id, name: TECHNIQUES[id]?.name ?? "(not in the built-in table)", state, by: [...new Set([...direct, ...viaSub, ...viaParent])] };
  });
  return { covered, byTactic, unknownTechniques: [...unknown].sort(), target: tgt };
}
