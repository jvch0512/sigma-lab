import { Cond, FieldTest, Rule, Selection } from "./sigma.js";

export type Event = Record<string, unknown>;

export class EventError extends Error {}

/** Flatten nested objects to dotted keys and lower-case the keys, so lookups are case-insensitive as in Sigma. */
export function flatten(o: Record<string, unknown>, prefix = "", out: Record<string, unknown> = {}): Record<string, unknown> {
  for (const [k, v] of Object.entries(o)) {
    const key = (prefix ? `${prefix}.${k}` : k).toLowerCase();
    if (v !== null && typeof v === "object" && !Array.isArray(v)) flatten(v as Record<string, unknown>, key, out); else out[key] = v;
  }
  return out;
}

export function parseEvents(text: string): { events: Event[]; expects: (string[] | null)[] } {
  const events: Event[] = [];
  const expects: (string[] | null)[] = [];
  const t = text.trim();
  let list: unknown[];
  if (t.startsWith("[")) {
    try { list = JSON.parse(t) as unknown[]; } catch { throw new EventError("events are not valid JSON"); }
  } else {
    list = t.split(/\r?\n/).filter((l) => l.trim() !== "").map((l, i) => {
      try { return JSON.parse(l) as unknown; } catch { throw new EventError(`line ${i + 1} is not valid JSON`); }
    });
  }
  list.forEach((e, i) => {
    if (typeof e !== "object" || e === null || Array.isArray(e)) throw new EventError(`event ${i + 1} must be an object`);
    const { _expect, ...rest } = e as Record<string, unknown>;
    if (_expect !== undefined && (!Array.isArray(_expect) || _expect.some((x) => typeof x !== "string"))) throw new EventError(`event ${i + 1}: _expect must be a list of rule ids`);
    events.push(flatten(rest));
    expects.push(_expect === undefined ? null : (_expect as string[]));
  });
  return { events, expects };
}

// ---- value matching
function wildcardRegex(p: string): RegExp {
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i]!;
    if (c === "\\" && (p[i + 1] === "*" || p[i + 1] === "?")) { re += "\\" + p[i + 1]; i++; }
    else if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`, "is");
}

const reCache = new Map<string, RegExp>();
function userRegex(p: string): RegExp {
  let r = reCache.get(p);
  if (!r) {
    let flags = "";
    let src = p;
    const m = /^\(\?([ims]+)\)/.exec(p);
    if (m) { flags = m[1]!; src = p.slice(m[0].length); }
    try { r = new RegExp(src, flags); } catch { throw new EventError(`invalid regular expression: ${p.slice(0, 60)}`); }
    if (reCache.size > 500) reCache.clear();
    reCache.set(p, r);
  }
  return r;
}

function windash(v: string): string[] { return [v, v.replace(/(^|\s)-/g, "$1/")]; }

function one(actual: unknown, ft: FieldTest, expected: string | number | boolean | null): boolean {
  if (expected === null) return actual === undefined || actual === null || actual === "";
  if (actual === undefined || actual === null) return false;
  const a = String(actual);
  const exp = String(expected);
  if (ft.mods.includes("re")) return userRegex(exp).test(a);
  if (ft.mods.some((m) => ["lt", "lte", "gt", "gte"].includes(m))) {
    const x = Number(a), y = Number(exp);
    return ft.mods.includes("lt") ? x < y : ft.mods.includes("lte") ? x <= y : ft.mods.includes("gt") ? x > y : x >= y;
  }
  const al = a.toLowerCase();
  const variants = ft.mods.includes("windash") ? windash(exp.toLowerCase()) : [exp.toLowerCase()];
  if (ft.mods.includes("contains")) return variants.some((v) => al.includes(v));
  if (ft.mods.includes("startswith")) return variants.some((v) => al.startsWith(v));
  if (ft.mods.includes("endswith")) return variants.some((v) => al.endsWith(v));
  return variants.some((v) => (/[*?]/.test(v) ? wildcardRegex(v).test(a) : al === v));
}

function testField(ev: Event, ft: FieldTest): boolean {
  if (ft.mods.includes("exists")) {
    const want = ft.values[0] === true || String(ft.values[0]).toLowerCase() === "true";
    return (ev[ft.field.toLowerCase()] !== undefined) === want;
  }
  const raw = ev[ft.field.toLowerCase()];
  const actuals = Array.isArray(raw) ? raw : [raw];
  const all = ft.mods.includes("all");
  const hit = (v: string | number | boolean | null) => actuals.some((a) => one(a, ft, v));
  return all ? ft.values.every(hit) : ft.values.some(hit);
}

function evalSelection(sel: Selection, ev: Event): boolean {
  if (sel.kind === "keywords") {
    const vals = Object.values(ev).flatMap((v) => (Array.isArray(v) ? v : [v])).map((v) => String(v).toLowerCase());
    return sel.words.some((w) => { const p = w.toLowerCase(); return vals.some((v) => (/[*?]/.test(p) ? wildcardRegex(p).test(v) : v.includes(p))); });
  }
  return sel.alts.some((alt) => alt.every((ft) => testField(ev, ft)));
}

function matchNames(rule: Rule, pattern: string): string[] {
  const names = Object.keys(rule.selections);
  if (pattern.toLowerCase() === "them") return names;
  if (pattern.includes("*")) { const re = wildcardRegex(pattern); return names.filter((n) => re.test(n)); }
  return names.filter((n) => n === pattern);
}

export function evalCond(c: Cond, rule: Rule, ev: Event, memo: Map<string, boolean>): boolean {
  switch (c.op) {
    case "ref": {
      const sel = rule.selections[c.name];
      if (!sel) throw new EventError(`${rule.title}: condition refers to unknown selection "${c.name}"`);
      let v = memo.get(c.name);
      if (v === undefined) { v = evalSelection(sel, ev); memo.set(c.name, v); }
      return v;
    }
    case "not": return !evalCond(c.a, rule, ev, memo);
    case "and": return evalCond(c.a, rule, ev, memo) && evalCond(c.b, rule, ev, memo);
    case "or": return evalCond(c.a, rule, ev, memo) || evalCond(c.b, rule, ev, memo);
    case "of": {
      const names = matchNames(rule, c.pattern);
      if (names.length === 0) throw new EventError(`${rule.title}: "${c.pattern}" matches no selection`);
      const res = names.map((n) => evalCond({ op: "ref", name: n }, rule, ev, memo));
      return c.quant === "all" ? res.every(Boolean) : res.some(Boolean);
    }
  }
}

export function matches(rule: Rule, ev: Event): boolean {
  return evalCond(rule.condition, rule, ev, new Map());
}

/** Static check, run once before events: every reference in the condition must resolve. */
export function validateRule(rule: Rule): string | null {
  const walk = (c: Cond): string | null => {
    switch (c.op) {
      case "ref": return rule.selections[c.name] ? null : `${rule.title}: condition refers to unknown selection "${c.name}"`;
      case "not": return walk(c.a);
      case "and": case "or": return walk(c.a) ?? walk(c.b);
      case "of": return matchNames(rule, c.pattern).length ? null : `${rule.title}: "${c.pattern}" matches no selection`;
    }
  };
  return walk(rule.condition);
}
