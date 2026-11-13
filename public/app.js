import { parseEvents } from "/lib/engine.js";
import { parseRules } from "/lib/sigma.js";
import { parseTarget, runLab } from "/lib/lab.js";
import { labMarkdown } from "/lib/report.js";

const $ = (id) => document.getElementById(id);
function el(tag, text, cls) { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; }
function table(headers, rows, classes = []) {
  const t = document.createElement("table");
  const h = document.createElement("tr");
  headers.forEach((x) => h.append(el("th", x)));
  t.append(h);
  rows.forEach((r) => { const tr = document.createElement("tr"); r.forEach((c, i) => tr.append(el("td", String(c), classes[i] ? classes[i](c) : undefined))); t.append(tr); });
  return t;
}
function cards(items) {
  const box = el("div", undefined, "cards");
  for (const [label, value, cls] of items) { const c = el("div", undefined, `card ${cls ?? ""}`); c.append(el("b", String(value)), el("span", label)); box.append(c); }
  return box;
}
function panel(title, ...kids) { const p = el("div", undefined, "panel"); p.append(el("h2", title), ...kids); return p; }
function copyButton(getMd) {
  const b = el("button", "Copy markdown");
  b.type = "button";
  b.addEventListener("click", async () => { try { await navigator.clipboard.writeText(getMd()); b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy markdown"; }, 1500); } catch { /* clipboard blocked */ } });
  return b;
}
function downloadButton(getMd, name) {
  const b = el("button", "Download .md");
  b.type = "button";
  b.addEventListener("click", () => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([getMd()], { type: "text/markdown" })); a.download = name; a.click(); URL.revokeObjectURL(a.href); });
  return b;
}
async function sample(name) { return (await fetch(`/examples/${name}`)).text(); }
function showError(box, e) { box.replaceChildren(el("p", String(e.message ?? e), "err")); }
function setupTabs() {
  document.querySelectorAll("#tabs button").forEach((b) => b.addEventListener("click", () => {
    document.querySelectorAll("#tabs button").forEach((x) => x.classList.toggle("on", x === b));
    document.querySelectorAll(".tab").forEach((s) => { s.hidden = s.id !== `p-${b.dataset.tab}`; });
  }));
}
const cls = (map) => (v) => map[v] ?? "";


const pctText = (x) => (x === null ? "-" : `${Math.round(x * 100)}%`);

function run() {
  const out = $("out");
  out.replaceChildren();
  const rt = $("rules").value.trim();
  if (!rt) return;
  try {
    const { rules, errors } = parseRules(rt);
    const et = $("events").value.trim();
    const { events, expects } = et ? parseEvents(et) : { events: [], expects: [] };
    const res = runLab(rules, events, expects, parseTarget($("target").value));
    const md = labMarkdown(res, errors);
    const fp = res.results.reduce((n, r) => n + r.fp, 0);
    const fn = res.results.reduce((n, r) => n + r.fn, 0);
    const t = res.coverage.target;
    out.append(cards([["Rules", res.results.length, errors.length ? "warn" : "ok"], ["False positives", fp, fp ? "warn" : "ok"], ["Missed detections", fn, fn ? "bad" : "ok"], ["Profile covered", t.length ? `${t.filter((x) => x.state === "covered").length}/${t.length}` : "-"]]));
    if (errors.length) out.append(panel("Parse errors", ...errors.map((e) => el("p", e, "err"))));
    out.append(panel("Rules", table(["Rule", "Level", "Techniques", "Hits", "TP", "FP", "FN", "Precision", "Recall"], res.results.map((r) => [r.rule.title, r.rule.level, r.techniques.join(", ") || "-", r.hits.length, r.tp, r.fp, r.fn, pctText(r.precision), pctText(r.recall)]),
      [null, cls({ critical: "s-high", high: "s-high", medium: "s-medium", low: "s-low" })])));
    const lint = res.results.filter((r) => r.rule.warnings.length || r.problems.length);
    if (lint.length) out.append(panel("Lint", ...lint.map((r) => el("p", `${r.rule.title}: ${[...r.problems, ...r.rule.warnings].join("; ")}`))));
    const noisy = res.results.filter((r) => r.fp), missed = res.results.filter((r) => r.fn);
    if (noisy.length || missed.length) out.append(panel("Tune these", ...noisy.map((r) => el("p", `${r.rule.title}: unexpected hit on event ${r.fpAt.join(", ")}`)), ...missed.map((r) => el("p", `${r.rule.title}: expected but not matched on event ${r.fnAt.join(", ")}`, "err"))));
    if (t.length) out.append(panel("Threat profile", table(["Technique", "Name", "State", "Rules"], t.map((x) => [x.id, x.name, x.state, x.by.join(", ") || "-"]), [null, null, cls({ covered: "s-low", partial: "s-medium", gap: "s-high" })])));
    out.append(panel("ATT&CK coverage by tactic", ...res.coverage.byTactic.map((x) => el("p", `${x.tactic}: ${x.techniques.join(", ")}`))));
    const row = el("div", undefined, "row");
    row.append(copyButton(() => md), downloadButton(() => md, "sigma-lab-report.md"));
    out.append(row);
  } catch (e) { showError(out, e); }
}

$("sample").addEventListener("click", async () => {
  [$("rules").value, $("events").value, $("target").value] = await Promise.all([sample("rules.yml"), sample("events.jsonl"), sample("threat-profile.txt")]);
  run();
});
for (const id of ["rules", "events", "target"]) $(id).addEventListener("input", run);
