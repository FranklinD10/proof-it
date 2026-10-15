//! End-to-end: TypeScript source → facts → obligations → Lean kernel.
//! Skipped (with a message) when Lean is not installed.

use proof_it_core::config::{Config, OrgPolicy};
use proof_it_core::facts::ProgramFacts;
use proof_it_core::property::Registry;
use proof_it_core::store::{ProofCache, RunStore, evidence_base};
use proof_it_core::types::ProofStatus;
use proof_it_model::extract::ExtractContext;
use proof_it_model::formal::{FormalOptions, run};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[test]
fn sample_verdicts() {
    if proof_it_model::lean::runner::toolchain().is_none() {
        eprintln!("SKIPPED: Lean not installed");
        return;
    }
    let text = include_str!("../../lang-ts/tests/fixtures/sample.ts");
    let a = proof_it_lang_ts::analyze("src/sample.ts", text, &HashSet::new()).expect("parse");
    let facts = ProgramFacts { modules: vec![a.facts], texts: vec![("src/sample.ts".into(), a.text)], parse_errors: vec![] };
    let reg = Registry::load(None).expect("library");
    let props: Vec<_> = reg.select(&["STATE-001".into(), "PAY-001".into(), "PAY-003".into(), "AUTHZ-001".into()], &[]);
    let dir = tempfile::tempdir().expect("tmp");
    let base = evidence_base(dir.path(), None).expect("base");
    let store = RunStore::create(&base).expect("store");
    let cfg = Config::default();
    let org = OrgPolicy::default();
    let ctx = ExtractContext { facts: &facts, config: &cfg, org: &org };
    let opts = FormalOptions { seed: 1, search_budget: 200_000, timeout: Duration::from_secs(120), parallel: true, max_proofs: 100, hints_dir: None };
    let out = run(&props, &ctx, &store, &ProofCache::new(&base, false), &opts);
    let by: HashMap<String, ProofStatus> = out.results.iter().map(|r| (format!("{} {}", r.property_id, r.target), r.status())).collect();
    for r in &out.results {
        eprintln!("{:<10} {:<9} {}\n    {}", r.status().label(), r.property_id, r.target, r.reason);
    }
    let get = |p: &str, t: &str| by.iter().find(|(k, _)| k.starts_with(p) && k.contains(t)).map(|(_, v)| *v);
    assert_eq!(get("STATE-001", "CANCELLED"), Some(ProofStatus::Proven));
    assert_eq!(get("STATE-001", "RESOLVED"), Some(ProofStatus::Violated));
    assert_eq!(get("PAY-001", "transfer"), Some(ProofStatus::Proven));
    assert_eq!(get("PAY-003", "transfer"), Some(ProofStatus::Violated));
    assert_eq!(get("AUTHZ-001", "/records/:id"), Some(ProofStatus::Violated));
    assert_eq!(get("AUTHZ-001", "/safe/:id"), Some(ProofStatus::Proven));
    // Every PROVEN result carries a kernel-checked non-vacuity witness.
    for r in out.results.iter().filter(|r| r.status() == ProofStatus::Proven) {
        let q = r.quality.as_ref().expect("quality");
        assert!(q.kernel_checked);
        assert_eq!(q.non_vacuity, proof_it_core::types::NonVacuity::KernelCheckedWitness, "{}", r.target);
    }
    // Every VIOLATED result carries a Lean-certified counterexample.
    for r in out.results.iter().filter(|r| r.status() == ProofStatus::Violated) {
        assert!(r.counterexample.as_ref().and_then(|c| c.lean_certificate.as_ref()).is_some(), "{}", r.target);
    }
}

/// `router.use(auth, adminMiddleware)` with imported middleware: the last
/// argument is middleware, not a mounted router, and must guard the routes.
/// Before, it was taken for a router module and the guard was dropped, so a
/// role-checked admin route was reported VIOLATED.
#[test]
fn imported_middleware_in_router_use_guards_routes() {
    if proof_it_model::lean::runner::toolchain().is_none() {
        eprintln!("SKIPPED: Lean not installed");
        return;
    }
    let files = [
        (
            "src/middleware/admin.ts",
            r#"
export const adminMiddleware = (req: any, res: any, next: any) => {
  if (!req.user) return res.status(401).json({ error: 'auth' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  next();
};
"#,
        ),
        (
            "src/middleware/auth.ts",
            r#"
import jwt from 'jsonwebtoken';
export const authMiddleware = (req: any, res: any, next: any) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'no token' });
  req.user = jwt.verify(token, process.env.JWT_SECRET as string);
  next();
};
"#,
        ),
        (
            "src/routes/admin.ts",
            r#"
import { Router } from 'express';
import { authMiddleware } from '../middleware/auth';
import { adminMiddleware } from '../middleware/admin';
const router = Router();
router.use(authMiddleware, adminMiddleware);
router.get('/admin/reports', async (req: any, res: any) => {
  const reports = await db.report.findMany({});
  res.json(reports);
});
export default router;
"#,
        ),
    ];
    let known: HashSet<String> = files.iter().map(|(p, _)| (*p).to_owned()).collect();
    let analysed: Vec<_> = files.iter().map(|(p, t)| proof_it_lang_ts::analyze(p, t, &known).expect("parse")).collect();
    let mount = analysed[2].facts.mounts.first().expect("router.use recorded");
    assert_eq!(mount.target_module.as_deref(), Some("src/middleware/admin.ts"));
    assert_eq!(mount.target_text.as_deref(), Some("adminMiddleware"));

    let facts = ProgramFacts {
        modules: analysed.iter().map(|a| a.facts.clone()).collect(),
        texts: analysed.iter().map(|a| (a.facts.file.clone(), a.text.clone())).collect(),
        parse_errors: vec![],
    };
    let reg = Registry::load(None).expect("library");
    let props: Vec<_> = reg.select(&["AUTHZ-002".into()], &[]);
    let dir = tempfile::tempdir().expect("tmp");
    let base = evidence_base(dir.path(), None).expect("base");
    let store = RunStore::create(&base).expect("store");
    let cfg = Config::default();
    let org = OrgPolicy::default();
    let ctx = ExtractContext { facts: &facts, config: &cfg, org: &org };
    let opts = FormalOptions { seed: 1, search_budget: 200_000, timeout: Duration::from_secs(120), parallel: true, max_proofs: 100, hints_dir: None };
    let out = run(&props, &ctx, &store, &ProofCache::new(&base, false), &opts);
    let r = out.results.iter().find(|r| r.target.contains("/admin/reports")).expect("route analysed");
    eprintln!("{} {} {}", r.status().label(), r.target, r.reason);
    assert_ne!(r.status(), ProofStatus::Violated, "the role check in adminMiddleware guards the route");
}
