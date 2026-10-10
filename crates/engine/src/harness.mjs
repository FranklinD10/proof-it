// Proof-It execution harness. Runs INSIDE the sandbox (bubblewrap + Node's
// permission model). It imports one module from the transpiled copy of the
// analysed repository and calls one export with JSON-encoded arguments.
// This is the only JavaScript in Proof-It: it exists because the code under
// test is JavaScript.
import { pathToFileURL } from "node:url";

function enc(v, depth = 0) {
  if (depth > 6) return "[depth]";
  if (typeof v === "number") {
    if (Number.isNaN(v)) return { $num: "NaN" };
    if (!Number.isFinite(v)) return { $num: v > 0 ? "Infinity" : "-Infinity" };
    return v;
  }
  if (typeof v === "bigint") return { $bigint: String(v) };
  if (v === undefined) return { $undefined: true };
  if (typeof v === "function") return "[function]";
  if (Array.isArray(v)) return v.slice(0, 50).map((x) => enc(x, depth + 1));
  if (v && typeof v === "object") {
    const o = {};
    for (const k of Object.keys(v).slice(0, 50)) o[k] = enc(v[k], depth + 1);
    return o;
  }
  return v;
}
function dec(v) {
  if (Array.isArray(v)) return v.map(dec);
  if (v && typeof v === "object") {
    if ("$num" in v) return Number(v.$num);
    if ("$undefined" in v) return undefined;
    if ("$alias" in v) return { $alias: v.$alias };
    const o = {};
    for (const k of Object.keys(v)) o[k] = dec(v[k]);
    return o;
  }
  return v;
}

let input = "";
process.stdin.setEncoding("utf8");
for await (const chunk of process.stdin) input += chunk;
const spec = JSON.parse(input);
let mod;
try {
  mod = await import(pathToFileURL(spec.module).href);
} catch (e) {
  process.stdout.write(JSON.stringify({ loadError: String((e && e.message) || e) }));
  process.exit(0);
}
const fn = spec.exportName.split(".").reduce((o, k) => (o == null ? o : o[k]), mod) ?? mod.default?.[spec.exportName];
if (typeof fn !== "function") {
  process.stdout.write(JSON.stringify({ loadError: `export ${spec.exportName} is not a function` }));
  process.exit(0);
}
const outcomes = [];
for (const c of spec.cases) {
  let args = c.args.map(dec);
  // { $alias: i } makes this argument the same object as argument i (aliasing attacks).
  args = args.map((a) => (a && typeof a === "object" && "$alias" in a ? args[a.$alias] : a));
  const o = { threw: false };
  try {
    let r = fn(...args);
    if (r && typeof r.then === "function") {
      r = await Promise.race([r, new Promise((_, rej) => setTimeout(() => rej(new Error("case timeout")), spec.caseTimeoutMs))]);
    }
    o.returned = enc(r);
  } catch (e) {
    o.threw = true;
    o.error = String((e && e.message) || e).slice(0, 300);
  }
  o.args = args.map((a) => enc(a));
  outcomes.push(o);
}
process.stdout.write(JSON.stringify({ outcomes }));
process.exit(0);
