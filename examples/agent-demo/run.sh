#!/usr/bin/env bash
# Proof-It agent demo: an AI-generated change whose unit tests pass is blocked
# by Proof-It, the agent repairs it from the structured counterexample, and the
# repaired change is proven. A third variant shows an agent trying to weaken
# the verification policy instead of fixing the code.
#
# Usage: examples/agent-demo/run.sh [path-to-proof-it-binary]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$HERE/../../target/release/proof-it}"
[ -x "$BIN" ] || BIN="$HERE/../../target/debug/proof-it"
WORK="$(mktemp -d)"
POLICY_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK" "$POLICY_DIR"' EXIT

# Trusted organisation policy, OUTSIDE the repository.
cat > "$POLICY_DIR/policy.yaml" <<'YAML'
protected_properties: [AUTHZ-001]
merge_policy:
  critical: [formal_proof, security_pass, regression_pass, no_violation]
  high: [security_pass, regression_pass, no_violation]
  normal: [regression_pass, no_violation]
  policy_changes_require_human: true
YAML

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
git_() { git -C "$WORK" -c user.name=demo -c user.email=demo@example.com "$@"; }

say "1. Base commit: an emergency service with an ownership-checked endpoint"
cp -r "$HERE/base/." "$WORK/"
git_ init -q -b main && git_ add -A && git_ commit -q -m "base: emergency service"
"$BIN" assure "$WORK" --offline --no-external --policy "$POLICY_DIR/policy.yaml" --quiet || true
BASE_RUN="$(cat "$WORK/.proof-it/runs/LATEST")"

say "2. AI agent adds 'GET /emergencies/:id/location'. Its unit tests pass:"
git_ checkout -q -b agent/location
cp "$HERE/change-ai/routes.ts" "$WORK/src/routes.ts"
cp "$HERE/change-ai/routes.test.ts" "$WORK/src/routes.test.ts"
git_ add -A && git_ commit -q -m "feat: expose emergency location (AI-generated)"
node "$HERE/run-tests.mjs" "$WORK/src/routes.test.ts"

say "3. Proof-It checks the change (agent protocol, structured JSON):"
set +e
"$BIN" check "$WORK" --offline --no-external --policy "$POLICY_DIR/policy.yaml" --diff main...agent/location --baseline "$BASE_RUN" --agent coding-agent > "$WORK/check.json"
echo "exit code: $?"
set -e
node -e 'const r=require(process.argv[1]); console.log(JSON.stringify({status:r.status, merge_decision:r.merge_decision, failures:r.failures.filter(f=>f.kind!=="finding").map(f=>({kind:f.kind,property:f.property,reason:f.reason.slice(0,140),source:f.source&&`${f.source.file}:${f.source.line}`,counterexample:f.counterexample&&f.counterexample.steps}))},null,2))' "$WORK/check.json"

say "4. Variant: the agent tries to make the check pass by excluding AUTHZ-001"
git_ checkout -q -b agent/gaming agent/location
mkdir -p "$WORK/.proof-it"
printf 'version: 1\nproperties:\n  exclude: [AUTHZ-001]\n' > "$WORK/.proof-it/config.yaml"
git_ add -A && git_ commit -q -m "chore: tune verification config"
set +e
"$BIN" assure "$WORK" --offline --no-external --policy "$POLICY_DIR/policy.yaml" --diff main...agent/gaming --baseline "$BASE_RUN" --quiet
echo "exit code: $?"
set -e

say "5. The agent repairs the change using the counterexample"
git_ checkout -q agent/location
cp "$HERE/change-fixed/routes.ts" "$WORK/src/routes.ts"
git_ add -A && git_ commit -q -m "fix: check ownership before returning location"
set +e
"$BIN" assure "$WORK" --offline --no-external --policy "$POLICY_DIR/policy.yaml" --diff main...agent/location --baseline "$BASE_RUN" --plain | sed -n '/CHANGE/,$p'
echo "exit code: $?"
