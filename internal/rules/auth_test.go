package rules

import "testing"

func TestMissingSecurityRequirement(t *testing.T) {
	noGlobalNoOwn := check(t, "missing-security-requirement", docHeader+`
paths:
  /health:
    get: {responses: {"200": {description: ok}}}
`)
	if len(noGlobalNoOwn) != 1 || noGlobalNoOwn[0].Severity != High {
		t.Fatalf("got %+v, want 1 HIGH finding (no path parameter)", noGlobalNoOwn)
	}

	withPathParam := check(t, "missing-security-requirement", docHeader+`
paths:
  /users/{id}:
    parameters: [{name: id, in: path, schema: {type: string}}]
    get: {responses: {"200": {description: ok}}}
`)
	if len(withPathParam) != 1 || withPathParam[0].Severity != Critical {
		t.Fatalf("got %+v, want 1 CRITICAL finding (BOLA-shaped)", withPathParam)
	}

	explicitlyPublic := check(t, "missing-security-requirement", docHeader+`
paths:
  /health:
    get: {security: [], responses: {"200": {description: ok}}}
`)
	if len(explicitlyPublic) != 0 {
		t.Fatalf("got %+v, want 0 (explicit security: [] is a deliberate choice)", explicitlyPublic)
	}

	globalDefault := check(t, "missing-security-requirement", docHeader+`
security: [{bearerAuth: []}]
paths:
  /users:
    get: {responses: {"200": {description: ok}}}
`)
	if len(globalDefault) != 0 {
		t.Fatalf("got %+v, want 0 (inherits the global default)", globalDefault)
	}
}

func TestDanglingSecuritySchemeReference(t *testing.T) {
	bad := check(t, "dangling-security-scheme-reference", docHeader+`
security: [{bearerAuth: []}]
paths: {}
`)
	if len(bad) != 1 {
		t.Fatalf("got %+v, want 1 (bearerAuth is never defined)", bad)
	}

	good := check(t, "dangling-security-scheme-reference", docHeader+`
security: [{bearerAuth: []}]
paths: {}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`)
	if len(good) != 0 {
		t.Fatalf("got %+v, want 0", good)
	}

	perOperation := check(t, "dangling-security-scheme-reference", docHeader+`
paths:
  /users:
    get: {security: [{apiKey: []}], responses: {"200": {description: ok}}}
`)
	if len(perOperation) != 1 {
		t.Fatalf("got %+v, want 1 (apiKey referenced but never defined)", perOperation)
	}
}

func TestWeakHTTPBasicAuth(t *testing.T) {
	bad := check(t, "weak-http-basic-auth", docHeader+`
paths: {}
components:
  securitySchemes:
    basicAuth: {type: http, scheme: basic}
`)
	if len(bad) != 1 {
		t.Fatalf("got %+v, want 1", bad)
	}

	good := check(t, "weak-http-basic-auth", docHeader+`
paths: {}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`)
	if len(good) != 0 {
		t.Fatalf("got %+v, want 0", good)
	}
}

func TestAPIKeyInQueryString(t *testing.T) {
	bad := check(t, "api-key-in-query-string", docHeader+`
paths: {}
components:
  securitySchemes:
    apiKeyAuth: {type: apiKey, in: query, name: api_key}
`)
	if len(bad) != 1 {
		t.Fatalf("got %+v, want 1", bad)
	}

	good := check(t, "api-key-in-query-string", docHeader+`
paths: {}
components:
  securitySchemes:
    apiKeyAuth: {type: apiKey, in: header, name: X-API-Key}
`)
	if len(good) != 0 {
		t.Fatalf("got %+v, want 0", good)
	}
}
