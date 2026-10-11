# Property system

A **property** is the unit of assurance: Proof-It never asks "is this program
bug-free?", only "does this program satisfy property X?".

## Schema

Properties are YAML (`properties/<category>/<ID>.yaml` in the library,
`.proof-it/properties/**.yaml` in a project). Unknown keys are errors.

```yaml
id: AUTHZ-001                 # [A-Z][A-Z0-9]*-NNN
name: User resource isolation
category: authorization
severity: critical            # info | low | medium | high | critical
version: 1
description: …
rationale: …
languages: [typescript, javascript]   # languages whose checks cover this property (informational)
signals: ['req\.(params|query|body)']   # applicability regexes; none matching ⇒ NOT_APPLICABLE
formal:                       # optional: only if an extractor exists
  extractor: authz.ownership  # one of the extractors shipped with Proof-It
  model: authorization.resource_ownership
  theorem: user_cannot_access_foreign_resource
  reference: ProofIt.Authorization.guarded_handler_isolates
detectors: [SEC-IDOR]         # non-formal evidence for this property
proof_strategy: …
attack_strategy: …
testing: { fuzz: true, mutation: true }
assumptions: [ … ]            # copied into every result
threat_model: { actor: …, capabilities: [ … ], goal: … }
recommendation: …
origin: human                 # project properties only: human | ai-generated
```

Extractors: `state-machine.terminal`, `state-machine.forbidden`,
`authz.ownership`, `authz.write`, `authz.admin`, `ledger.conservation`,
`ledger.non-negative`.

## Library

`proof-it properties` lists all of them. Categories: authentication,
authorization, sessions, cryptography, data-integrity, payments,
state-machines, concurrency, distributed-systems, apis, databases,
infrastructure. Properties without a formal model report `NOT_MODELED` (with
detector evidence) or `NOT_APPLICABLE`.

## Project properties and state machines

- A project property may only reference shipped extractors; it cannot contain
  code and cannot reuse a library id.
- `origin: ai-generated` marks a candidate: its violations warn, never fail,
  until a human changes the origin.
- State machines are declared in `config.yaml` (`state_machines`) or the
  organisation policy. Without a declaration, terminal states are **inferred**
  from names (RESOLVED, CANCELLED, …) and reported as `[inferred spec]`.

## Binding code to properties

Automatic (route registrations, mounts, handler factories, state writes,
balance updates) or explicit with a doc tag:

```ts
/** @proof-it AUTHZ-001 */
export async function getRecord(req, res) { … }
```

## Authorization configuration

`authorization.ownership_fields` (default `ownerId, userId, owner, createdBy,
user_id, owner_id`), `principal_paths` (default `req.user.id`, `req.user.sub`,
…), `admin_roles` (default `admin, super_admin, superadmin`) and
`guard_functions` (functions you assert enforce ownership — recorded as an
assumption, and reported as a policy change when added).
