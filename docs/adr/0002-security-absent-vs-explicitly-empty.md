# 2. An operation with no security is not the same finding as one that declares itself public

Status: accepted — 2026-09-26

## Context

OpenAPI lets an operation either omit its `security` field entirely
(meaning "whatever the document's global default says applies"), give
it a non-empty array (its own specific requirement, overriding the
global default), or give it an explicit empty array, `security: []`
(meaning "no authentication required here, overriding any global
default that would otherwise apply"). A spec author reaches for
`security: []` deliberately, on endpoints like `/health` or `/login`
that are supposed to be reachable without a token.

A scanner that only checks "is there a non-empty security array" cannot
tell "nobody ever thought about auth here" from "someone thought about
it and decided this one endpoint doesn't need it" -- and flagging both
identically either trains people to ignore the finding on every public
health-check endpoint, or (worse) teaches them that adding `security:
[]` to make the warning go away is equivalent to actually securing
something.

## Decision

Every accessor that reads a security requirement --
`Document.GlobalSecurity()`, `Operation.EffectiveSecurity()` -- returns
`(value, ok bool)`, not just a possibly-nil slice. `ok` is `true` for a
present-but-empty array and `false` only when the field is absent
altogether. `missing-security-requirement` (`auth.go`) fires exactly
when `EffectiveSecurity` reports `ok == false`: no operation-level
field, and no global default either. An operation with `security: []`
-- explicit, deliberate -- produces no finding at all.

This is the same "absent is not the same as present-but-zero" principle
idbroker's `IdTokenClaims` applies to optional JWT claims and kubeshield
applies to Kubernetes' unset-vs-explicit-false securityContext fields,
here applied to a document schema instead of a Go struct.

## Consequences

- The severity itself also depends on more than presence: an operation
  whose path carries a parameter (`/users/{id}`) and has no security
  anywhere is scored Critical, not just High, because a missing
  authorization check on a per-resource endpoint is specifically the
  BOLA/IDOR shape OWASP API Security's #1 risk describes -- a bare
  `/health` with the same gap is a real problem but a different, less
  severe one.
- `dangling-security-scheme-reference` is a genuinely separate rule from
  `missing-security-requirement` on purpose: an operation that inherits
  a global `security: [{oauth: []}]` where `oauth` was never defined in
  `components.securitySchemes` has *some* stated intent to require
  authentication, which this tool credits -- the fact that the intent is
  broken is reported, but not conflated with "nobody thought about
  this endpoint at all."
- What this does not do: verify that a declared security scheme is
  actually enforced by the running service, or that the scopes listed
  in a requirement (`{oauth: [read:users]}`) match what the operation
  actually needs. A document is a claim about what should happen; this
  tool checks the claim is coherent and present, not that the
  implementation honours it.
