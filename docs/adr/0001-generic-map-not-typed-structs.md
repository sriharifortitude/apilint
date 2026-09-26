# 1. The OpenAPI document is read as a generic map, with local-only $ref resolution

Status: accepted — 2026-09-26

## Context

A tool that reads OpenAPI documents can either decode into a full typed
model (a struct per object the specification defines -- `Operation`,
`Schema`, `SecurityScheme`, ...) via a schema-aware library, or decode
into a generic tree and read only the handful of fields its own rules
actually need. A typed model is more convenient once it exists, but
OpenAPI 3.x's schema is large, has several optional and mutually
exclusive shapes (a parameter can carry a `schema` or `content`, a
response's `content` is keyed by arbitrary media type strings), and a
full library is a real dependency to trust for a tool whose only other
external dependency is a YAML parser.

## Decision

`internal/spec` decodes into `map[string]any` (mirroring kubeshield's
approach to Kubernetes manifests) and provides exactly the accessors its
rules need: `Operations()` (flattened, with parameters merged per the
spec's own path-item/operation override rule), `ResolveRef` /
`WalkProperties` (following `$ref`), `SecuritySchemeNames`, `Servers`.
Everything else in the document -- extensions, tags, external docs --
is simply never read, not modelled and ignored.

`$ref` resolution is local-only: `#/components/schemas/User` resolves,
`./other-file.yaml#/components/schemas/User` does not (`ResolveRef`
returns `false` for anything not starting with `#/`). Most real-world
specs, especially the single-file ones a CI pipeline would actually
lint, use local refs exclusively; multi-file specs are common in larger
API programs but are a genuinely different, larger problem (fetching
and caching remote documents, detecting cycles across files) that this
version does not attempt.

The parser also requires a top-level `openapi` field specifically --
Swagger 2.0 documents (`"swagger": "2.0"`) are rejected outright, not
partially read with fields that don't apply.

## Consequences

- Adding a new rule never requires touching the parser; it only needs
  whatever accessor already exists, or a small new one, on `*Document`.
- A schema that uses `allOf`/`oneOf`/`anyOf` composition is not
  flattened -- `WalkProperties` reads a schema's own `properties` and
  `items`, not the properties an `allOf` branch would contribute. A
  request or response schema built entirely from composition will
  under-report on the field-name-based rules (`sensitive-field-in-
  response`, `mass-assignment-risk`, `missing-format-constraint`), a
  real gap stated here rather than discovered by a false clean scan.
- `WalkProperties` bounds its own recursion (`MaxSchemaWalkDepth`)
  specifically because a generic map has no built-in way to detect a
  self-referential schema (a `Comment` whose `replies` is an array of
  `Comment`) except by depth -- a typed model with the same shape would
  have exactly the same problem, so this is not a cost unique to the
  generic-map choice, just one this package has to actually pay
  attention to. `spec_test.go` proves it terminates on exactly that
  shape, with a timeout that fails the test rather than hanging the
  suite if a future change reintroduces unbounded recursion.
