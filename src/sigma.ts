import { YamlError, YamlValue, parseYaml } from "./yaml.js";

export type Level = "informational" | "low" | "medium" | "high" | "critical";
export interface FieldTest { field: string; mods: string[]; values: (string | number | boolean | null)[] }
export type Selection = { kind: "maps"; alts: FieldTest[][] } | { kind: "keywords"; words: string[] };

export type Cond =
  | { op: "ref"; name: string }
  | { op: "not"; a: Cond }
  | { op: "and" | "or"; a: Cond; b: Cond }
  | { op: "of"; quant: "1" | "all"; pattern: string };

export interface Rule {
  id: string;
  title: string;
  status: string;
  description: string;
  level: Level;
  tags: string[];
  logsource: Record<string, string>;
  falsepositives: string[];
  selections: Record<string, Selection>;
  condition: Cond;
  conditionText: string;
  warnings: string[];
}

export class RuleError extends Error {}

const LEVELS: Level[] = ["informational", "low", "medium", "high", "critical"];
const isObj = (v: unknown): v is { [k: string]: YamlValue } => typeof v === "object" && v !== null && !Array.isArray(v);
const asList = (v: YamlValue | undefined): YamlValue[] => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
const MODS = new Set(["contains", "startswith", "endswith", "all", "re", "exists", "windash", "base64", "base64offset", "cidr", "lt", "lte", "gt", "gte", "i", "m", "s"]);

function fieldTest(key: string, val: YamlValue): FieldTest {
  const [field, ...mods] = key.split("|");
  if (!field) throw new RuleError(`empty field name in "${key}"`);
  for (const m of mods) if (!MODS.has(m)) throw new RuleError(`unsupported modifier "${m}" in "${key}"`);
  const values = asList(val).map((x) => {
    if (typeof x === "object" && x !== null) throw new RuleError(`nested value under "${key}"`);
    return x as string | number | boolean | null;
  });
  if (values.length === 0) values.push(null);
  return { field, mods, values };
}

function selection(name: string, v: YamlValue): Selection {
  if (isObj(v)) return { kind: "maps", alts: [Object.entries(v).map(([k, x]) => fieldTest(k, x))] };
  if (Array.isArray(v)) {
    if (v.every((x) => typeof x !== "object" || x === null)) return { kind: "keywords", words: v.map((x) => String(x)) };
    if (v.every(isObj)) return { kind: "maps", alts: v.map((m) => Object.entries(m as { [k: string]: YamlValue }).map(([k, x]) => fieldTest(k, x))) };
    throw new RuleError(`selection "${name}" mixes keywords and maps`);
  }
  throw new RuleError(`selection "${name}" must be a map or a list`);
}

// ---- condition parser
function tokenize(s: string): string[] {
  const out: string[] = [];
  const re = /\s*(\(|\)|[^\s()]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out.push(m[1]!);
  return out;
}

export function parseCondition(text: string): Cond {
  if (text.includes("|")) throw new RuleError("aggregation conditions (count, near, temporal) are not supported");
  const t = tokenize(text);
  let i = 0;
  const peek = () => t[i]?.toLowerCase();
  function atom(): Cond {
    const tok = t[i];
    if (tok === undefined) throw new RuleError("condition ends unexpectedly");
    if (tok === "(") { i++; const e = or(); if (t[i] !== ")") throw new RuleError("missing )"); i++; return e; }
    const low = tok.toLowerCase();
    if ((low === "1" || low === "all" || low === "any") && t[i + 1]?.toLowerCase() === "of") {
      const pattern = t[i + 2];
      if (pattern === undefined) throw new RuleError('"of" needs a selection name, a pattern or "them"');
      i += 3;
      return { op: "of", quant: low === "all" ? "all" : "1", pattern };
    }
    if (["and", "or", "not", ")"].includes(low)) throw new RuleError(`unexpected "${tok}" in condition`);
    i++;
    return { op: "ref", name: tok };
  }
  function not(): Cond { if (peek() === "not") { i++; return { op: "not", a: not() }; } return atom(); }
  function and(): Cond { let a = not(); while (peek() === "and") { i++; a = { op: "and", a, b: not() }; } return a; }
  function or(): Cond { let a = and(); while (peek() === "or") { i++; a = { op: "or", a, b: and() }; } return a; }
  const c = or();
  if (i < t.length) throw new RuleError(`unexpected "${t[i]}" in condition`);
  return c;
}

export function parseRule(doc: YamlValue): Rule {
  if (!isObj(doc)) throw new RuleError("a rule must be a mapping");
  const title = typeof doc["title"] === "string" ? doc["title"] : "";
  if (!title) throw new RuleError("rule has no title");
  const det = doc["detection"];
  if (!isObj(det)) throw new RuleError(`${title}: no detection section`);
  const cond = det["condition"];
  const conditionText = Array.isArray(cond) ? cond.map(String).join(" or ") : typeof cond === "string" ? cond : "";
  if (!conditionText) throw new RuleError(`${title}: detection has no condition`);
  const selections: Record<string, Selection> = {};
  for (const [k, v] of Object.entries(det)) if (k !== "condition" && k !== "timeframe") selections[k] = selection(k, v);
  let condition: Cond;
  try { condition = parseCondition(conditionText); } catch (e) { throw new RuleError(`${title}: ${(e as Error).message}`); }
  const warnings: string[] = [];
  const level = typeof doc["level"] === "string" && LEVELS.includes(doc["level"] as Level) ? (doc["level"] as Level) : "medium";
  if (doc["level"] === undefined) warnings.push("no level");
  const tags = asList(doc["tags"]).map(String);
  if (!tags.some((t) => /^attack\.t\d{4}/i.test(t))) warnings.push("no ATT&CK technique tag");
  if (typeof doc["description"] !== "string" || doc["description"].length < 20) warnings.push("missing or very short description");
  if (asList(doc["falsepositives"]).length === 0) warnings.push("no falsepositives documented");
  if (typeof doc["id"] !== "string") warnings.push("no id");
  const ls: Record<string, string> = {};
  if (isObj(doc["logsource"])) for (const [k, v] of Object.entries(doc["logsource"])) ls[k] = String(v);
  else warnings.push("no logsource");
  for (const [name, sel] of Object.entries(selections)) {
    if (sel.kind === "maps") for (const alt of sel.alts) for (const ft of alt) {
      if (ft.mods.includes("contains") && ft.values.some((v) => typeof v === "string" && v.length < 4)) warnings.push(`${name}: "${ft.field}|contains" with a very short value will be noisy`);
      if (ft.values.some((v) => v === "*")) warnings.push(`${name}: "${ft.field}" matches anything`);
    }
  }
  return {
    id: typeof doc["id"] === "string" ? doc["id"] : title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""),
    title, status: typeof doc["status"] === "string" ? doc["status"] : "", description: typeof doc["description"] === "string" ? doc["description"] : "",
    level, tags, logsource: ls, falsepositives: asList(doc["falsepositives"]).map(String), selections, condition, conditionText, warnings,
  };
}

/** Split a multi-document YAML text on `---` lines and parse every rule. Errors are collected per document. */
export function parseRules(text: string): { rules: Rule[]; errors: string[] } {
  const docs = text.split(/^---\s*$/m).filter((d) => d.trim() !== "");
  const rules: Rule[] = [];
  const errors: string[] = [];
  docs.forEach((d, i) => {
    try { rules.push(parseRule(parseYaml(d))); } catch (e) {
      if (e instanceof RuleError || e instanceof YamlError) errors.push(`rule ${i + 1}: ${e.message}`); else throw e;
    }
  });
  const seen = new Set<string>();
  for (const r of rules) { if (seen.has(r.id)) errors.push(`duplicate rule id: ${r.id}`); seen.add(r.id); }
  return { rules, errors };
}
