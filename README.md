# apilint

[![CI](https://github.com/sriharifortitude/apilint/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/apilint/actions/workflows/ci.yml)

A static OpenAPI 3.x security linter: ten checks for OWASP API Security
Top 10 signals detectable from the spec alone -- no live server, no
running database, no two test accounts needed to prove one user can
reach another's data. This portfolio's other scanners each read one
kind of artifact: tfwarden reads a Terraform plan, kubeshield a
Kubernetes manifest, credsweep a git history, vulnlock a lockfile.
apilint reads the fifth: the contract an API makes with its callers,
which is where broken object-level authorization, mass assignment and
sensitive-data exposure -- three separate entries on OWASP's API Top
10 -- all show up before a single request is ever sent.

```
$ apilint scan --waivers testdata/waivers.yaml testdata/small.yaml

FAIL          (global security)              CRITICAL security requirement names scheme "oauth", which is not defined in components.securitySchemes
              fix: define "oauth" under components.securitySchemes, or fix the typo if this was meant to reference an existing scheme
waived        (whole document)               LOW      no operation anywhere documents a 429 response
              waived 2030-01-01: rate limiting is enforced at the API gateway, outside this spec's control
FAIL          GET /users/{id} (200 response) CRITICAL response includes a field named "password", which looks like a credential or sensitive PII
              fix: remove "password" from the response schema, or mark it writeOnly: true if it genuinely never appears in a real response
FAIL          POST /users                    HIGH     request body accepts "role", which a client should not be able to set directly
              fix: remove "role" from the request schema and set it server-side, or document why this endpoint legitimately needs to accept it (e.g. an admin-only operation with its own authorization check)
FAIL          POST /users                    LOW      request field "email" has no format/pattern constraint, only type: string
              fix: add format: email to the schema for "email" so invalid input is rejected by validation, not by whatever code reads it later
FAIL          POST /users (201 response)     MEDIUM   the 201 response has no content/schema documented
              fix: document the response schema -- this tool (and anyone generating a client from this spec) cannot reason about what the endpoint actually returns without it
FAIL          components.securitySchemes.apiKeyAuth HIGH     an apiKey scheme with in: query puts the key in the URL, which is logged and cached far more readily than a header
              fix: move the API key to a header (in: header) instead of the query string
EXPIRED       components.securitySchemes.basicAuth HIGH     HTTP Basic sends the username and password on every request, reversibly encoded, not encrypted by the scheme itself
              fix: use a bearer token (OAuth2/OIDC access token, or a signed API key scheme) instead of HTTP Basic for anything beyond a quick internal tool
              WAIVER EXPIRED 2025-01-01: was meant to be removed once the OAuth migration finished
FAIL          servers[0]                     MEDIUM   server URL "http://api.example.com" is plain HTTP
              fix: use https:// -- credentials, tokens and response bodies otherwise cross the network unencrypted

9 findings: 7 failing, 1 waived, 1 expired waivers
$ echo $?
1
```

(Real output from `testdata/small.yaml` and `testdata/waivers.yaml` in
this repository, checked in CI against these exact strings -- run it
yourself with the command above. `testdata/clean.yaml` is fully
compliant and produces nothing, proving Pass is never asserted, only
the absence of a Fail.)

## The checks

| rule | severity | what it catches |
| --- | --- | --- |
| `missing-security-requirement` | Critical if the path has a parameter, High otherwise | no `security` on the operation and no global default -- distinct from an operation that declares `security: []` on purpose (see [ADR 2](docs/adr/0002-security-absent-vs-explicitly-empty.md)) |
| `dangling-security-scheme-reference` | Critical | a `security` requirement names a scheme `components.securitySchemes` never defines |
| `sensitive-field-in-response` | Critical | a 2xx response schema includes a field named like a credential or PII (`password`, `apiKey`, `ssn`, ...), not marked `writeOnly` |
| `mass-assignment-risk` | High | a write request body accepts `role`, `isAdmin`, `permissions`, or (on a create) a client-chosen `id` |
| `weak-http-basic-auth` | High | an `http`/`basic` security scheme |
| `api-key-in-query-string` | High | an `apiKey` scheme with `in: query` -- ends up in logs, browser history, the `Referer` header |
| `unencrypted-server-url` | Medium | a documented server URL using `http://` (`localhost` exempted) |
| `missing-response-schema` | Medium | a 2xx response with no documented content/schema -- nothing to check for over-exposure at all |
| `missing-format-constraint` | Low | a request field named `email`/`url`/`phone` with no `format`/`pattern`/`enum` |
| `missing-rate-limit-evidence` | Low | no operation anywhere documents a `429` response |

Every finding names the exact evidence and a one-line fix.
`docs/adr/` explains the two decisions that most shape the design.

## Waivers

Accepted risk is named per rule and per location (an operation like
`GET /users/{id}`, a component like `components.securitySchemes.
basicAuth`, or `(whole document)` for a spec-wide check), with a reason
and an expiry date, all four required:

```yaml
waivers:
  - rule: missing-rate-limit-evidence
    location: "(whole document)"
    reason: rate limiting is enforced at the API gateway, outside this spec's control
    expires: "2030-01-01"
```

An expired waiver stops suppressing its finding and shows as `WAIVER
EXPIRED`, still failing the gate.

## Output formats and exit codes

`--format terminal|json|sarif`, `--output FILE`, `--fail-on
low|medium|high|critical` (default `low`).

| exit code | meaning |
| --- | --- |
| 0 | nothing failing at or above `--fail-on` |
| 1 | at least one finding does (an expired waiver counts) |
| 2 | the spec or waivers file could not be read or parsed |

## Running it

    go install github.com/sriharifortitude/apilint/cmd/apilint@v0.1.0
    apilint scan openapi.yaml

Or the image: `docker run --rm -v "$PWD:/w" ghcr.io/sriharifortitude/apilint:0.1 scan /w/openapi.yaml`.

## Checks

    go build ./... && go vet ./... && staticcheck ./...
    go test ./... -cover

52 tests across five packages: `internal/spec` parses real multi-shape
OpenAPI YAML and JSON, resolves `$ref` at every nesting level, and
proves `WalkProperties` terminates on a self-referential schema rather
than hanging; `internal/rules` builds every fixture from real YAML
(not hand-built Go maps) covering each rule's fail/pass edges,
including the absent-vs-explicit-empty security distinction and the
id-on-create-vs-id-on-update mass-assignment distinction;
`internal/waiver` and `internal/report` are hand-verified against exact
text; `cmd/apilint` runs the whole pipeline against real files and
checks exit codes.

## What it deliberately does not do

- **No live server, no BOLA fuzzing with real accounts.** This checks
  whether the *contract* declares an authorization requirement, not
  whether the implementation actually enforces one per-resource --
  that requires two real user sessions and a running API, a materially
  different (and heavier) tool than a spec linter. See ADR 2's
  consequences section.
- **Local `$ref` only.** A `$ref` into another file is left
  unresolved, not fetched. See [ADR 1](docs/adr/0001-generic-map-not-typed-structs.md).
- **No `allOf`/`oneOf`/`anyOf` schema composition.** The field-name
  rules read a schema's own `properties`, not what a composition
  branch would contribute -- a real gap on specs that lean on
  composition, stated here rather than discovered as a false clean
  scan.
- **Swagger 2.0 is rejected outright**, not partially read.
- **No auto-remediation.** It tells you what's wrong and one way to
  fix it; it edits nothing.

## Licence

MIT.
