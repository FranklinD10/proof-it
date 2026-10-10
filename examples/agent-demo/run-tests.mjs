// Minimal test runner for the demo: strips types with Node's built-in support and runs `tests`.
const mod = await import(process.argv[2]);
let failed = 0;
for (const [name, fn] of Object.entries(mod.tests)) {
  try { fn(); console.log(`  ✓ ${name}`); } catch (e) { failed++; console.log(`  ✗ ${name}: ${e.message}`); }
}
console.log(failed ? `${failed} failing` : "all unit tests pass");
process.exitCode = failed ? 1 : 0;
