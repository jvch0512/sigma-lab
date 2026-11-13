/**
 * A small YAML subset parser, enough for Sigma rules: block mappings and sequences, quoted and plain scalars,
 * one-line flow sequences, `|` and `>` block scalars and comments. Anchors, tags and multi-line flow collections are rejected.
 */
export type YamlValue = string | number | boolean | null | YamlValue[] | { [k: string]: YamlValue };

export class YamlError extends Error {
  constructor(msg: string, public line: number) { super(`line ${line}: ${msg}`); }
}

interface Line { indent: number; text: string; no: number; raw: string }

function stripComment(s: string): string {
  let q = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (q) { if (c === q) { if (q === "'" && s[i + 1] === "'") i++; else q = ""; } else if (q === '"' && c === "\\") i++; continue; }
    if (c === "'" || c === '"') { if (i === 0 || /[\s:\[,{-]/.test(s[i - 1]!)) q = c; continue; }
    if (c === "#" && (i === 0 || /\s/.test(s[i - 1]!))) return s.slice(0, i);
  }
  return s;
}

function scalar(src: string, no: number): YamlValue {
  const s = src.trim();
  if (s === "") return null;
  if (s.startsWith('"')) {
    if (!s.endsWith('"') || s.length < 2) throw new YamlError("unterminated double-quoted string", no);
    return s.slice(1, -1).replace(/\\(["\\/nrt0])/g, (_, c: string) => ({ n: "\n", r: "\r", t: "\t", "0": "\0" } as Record<string, string>)[c] ?? c);
  }
  if (s.startsWith("'")) {
    if (!s.endsWith("'") || s.length < 2) throw new YamlError("unterminated single-quoted string", no);
    return s.slice(1, -1).replace(/''/g, "'");
  }
  if (s.startsWith("[")) return flowSeq(s, no);
  if (s.startsWith("{")) throw new YamlError("flow mappings are not supported", no);
  if (/^[&*!]/.test(s)) throw new YamlError("anchors, aliases and tags are not supported", no);
  if (s === "~" || /^null$/i.test(s)) return null;
  if (/^(true|false)$/i.test(s)) return s.toLowerCase() === "true";
  if (/^-?(0|[1-9]\d*)(\.\d+)?$/.test(s)) return Number(s);
  return s;
}

function flowSeq(s: string, no: number): YamlValue[] {
  if (!s.endsWith("]")) throw new YamlError("flow sequences must close on the same line", no);
  const body = s.slice(1, -1);
  const items: string[] = [];
  let cur = "", q = "";
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (q) { cur += c; if (c === q) q = ""; continue; }
    if (c === "'" || c === '"') { q = c; cur += c; continue; }
    if (c === ",") { items.push(cur); cur = ""; continue; }
    cur += c;
  }
  if (q) throw new YamlError("unterminated string in flow sequence", no);
  if (cur.trim() !== "" || items.length) items.push(cur);
  return items.filter((x, i) => !(x.trim() === "" && i === items.length - 1)).map((x) => scalar(x, no));
}

function splitKey(text: string): { key: string; rest: string } | null {
  let q = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (q) { if (c === q) q = ""; continue; }
    if ((c === "'" || c === '"') && i === 0) { q = c; continue; }
    if (c === ":" && (i + 1 === text.length || text[i + 1] === " ")) {
      let key = text.slice(0, i).trim();
      if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) key = key.slice(1, -1);
      return { key, rest: text.slice(i + 1) };
    }
  }
  return null;
}

export function parseYaml(src: string): YamlValue {
  const rawLines = src.replace(/\r\n?/g, "\n").split("\n");
  const lines: Line[] = [];
  rawLines.forEach((raw, i) => {
    if (/^\t/.test(raw) || /^ *\t/.test(raw)) { if (raw.trim() !== "") throw new YamlError("tabs are not allowed for indentation", i + 1); }
    const t = stripComment(raw);
    if (t.trim() === "" || t.trim() === "---") return;
    lines.push({ indent: t.length - t.trimStart().length, text: t.trim(), no: i + 1, raw });
  });
  let pos = 0;

  function blockScalar(style: string, parentIndent: number, startNo: number): string {
    // consume raw lines after the header that are blank or more indented than the parent
    const start = lines[pos - 1] ? lines[pos - 1]!.no - 1 : startNo - 1;
    const out: string[] = [];
    let indent = -1;
    let i = start + 1;
    for (; i < rawLines.length; i++) {
      const r = rawLines[i]!;
      if (r.trim() === "") { out.push(""); continue; }
      const ind = r.length - r.trimStart().length;
      if (ind <= parentIndent) break;
      if (indent < 0) indent = ind;
      out.push(r.slice(Math.min(indent, ind)));
    }
    while (out.length && out[out.length - 1] === "") out.pop();
    // skip structured lines that were consumed
    while (pos < lines.length && lines[pos]!.no <= i) pos++;
    return style.startsWith("|") ? out.join("\n") : out.join(" ").replace(/\s+/g, " ").trim();
  }

  function value(rest: string, parentIndent: number, no: number): YamlValue {
    const r = rest.trim();
    if (r === "|" || r === ">" || /^[|>][+-]?$/.test(r)) return blockScalar(r, parentIndent, no);
    if (r === "") {
      const n = lines[pos];
      if (n && (n.indent > parentIndent || (n.indent === parentIndent && n.text.startsWith("- ")))) return block(n.indent);
      return null;
    }
    return scalar(r, no);
  }

  function block(indent: number): YamlValue {
    const first = lines[pos]!;
    if (first.text.startsWith("- ") || first.text === "-") return sequence(indent);
    return mapping(indent);
  }

  function sequence(indent: number): YamlValue[] {
    const out: YamlValue[] = [];
    while (pos < lines.length) {
      const l = lines[pos]!;
      if (l.indent !== indent || !(l.text.startsWith("- ") || l.text === "-")) break;
      pos++;
      const rest = l.text === "-" ? "" : l.text.slice(2);
      const kv = rest.trim() !== "" && !rest.trim().startsWith("[") && !/^["']/.test(rest.trim()) ? splitKey(rest) : null;
      if (kv) {
        // "- key: value": the mapping continues on following lines indented past the dash
        const innerIndent = indent + (l.text.length - rest.length);
        const obj: { [k: string]: YamlValue } = {};
        obj[kv.key] = value(kv.rest, innerIndent - 1, l.no);
        while (pos < lines.length && lines[pos]!.indent === innerIndent && !lines[pos]!.text.startsWith("- ")) {
          const n = lines[pos]!;
          const kv2 = splitKey(n.text);
          if (!kv2) throw new YamlError("expected key: value", n.no);
          pos++;
          obj[kv2.key] = value(kv2.rest, innerIndent, n.no);
        }
        out.push(obj);
      } else if (rest.trim() === "") {
        const n = lines[pos];
        out.push(n && n.indent > indent ? block(n.indent) : null);
      } else out.push(scalar(rest, l.no));
    }
    return out;
  }

  function mapping(indent: number): { [k: string]: YamlValue } {
    const out: { [k: string]: YamlValue } = {};
    while (pos < lines.length) {
      const l = lines[pos]!;
      if (l.indent < indent) break;
      if (l.indent > indent) throw new YamlError("unexpected indentation", l.no);
      if (l.text.startsWith("- ")) break;
      const kv = splitKey(l.text);
      if (!kv) throw new YamlError("expected key: value", l.no);
      if (Object.prototype.hasOwnProperty.call(out, kv.key)) throw new YamlError(`duplicate key "${kv.key}"`, l.no);
      pos++;
      out[kv.key] = value(kv.rest, indent, l.no);
    }
    return out;
  }

  if (lines.length === 0) return null;
  const v = block(lines[0]!.indent);
  if (pos < lines.length) throw new YamlError("unexpected content", lines[pos]!.no);
  return v;
}
