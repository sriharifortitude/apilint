package spec

import "testing"

func findOp(t *testing.T, ops []Operation, method, path string) Operation {
	t.Helper()
	for _, op := range ops {
		if op.Method == method && op.Path == path {
			return op
		}
	}
	t.Fatalf("no operation %s %s in %+v", method, path, ops)
	return Operation{}
}

func TestOperationsFlattensEveryMethodOnEveryPath(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths:
  /users:
    get: {responses: {"200": {description: ok}}}
    post: {responses: {"201": {description: created}}}
  /users/{id}:
    delete: {responses: {"204": {description: ok}}}
`))
	if err != nil {
		t.Fatal(err)
	}
	ops := doc.Operations()
	if len(ops) != 3 {
		t.Fatalf("got %d operations, want 3: %+v", len(ops), ops)
	}
}

func TestOperationSecurityDistinguishesAbsentFromExplicitEmpty(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
security: [{bearerAuth: []}]
paths:
  /inherits-global:
    get: {responses: {"200": {description: ok}}}
  /explicitly-public:
    get: {security: [], responses: {"200": {description: ok}}}
  /overrides-global:
    get: {security: [{apiKey: []}], responses: {"200": {description: ok}}}
`))
	if err != nil {
		t.Fatal(err)
	}
	ops := doc.Operations()

	inherits := findOp(t, ops, "get", "/inherits-global")
	sec, ok := inherits.EffectiveSecurity(doc)
	if !ok || len(sec) != 1 {
		t.Errorf("inherits-global: EffectiveSecurity = %+v, %v, want the global default", sec, ok)
	}

	public := findOp(t, ops, "get", "/explicitly-public")
	sec, ok = public.EffectiveSecurity(doc)
	if !ok || len(sec) != 0 {
		t.Errorf("explicitly-public: EffectiveSecurity = %+v, %v, want an explicit empty list", sec, ok)
	}

	overridden := findOp(t, ops, "get", "/overrides-global")
	sec, ok = overridden.EffectiveSecurity(doc)
	if !ok || len(sec) != 1 {
		t.Errorf("overrides-global: EffectiveSecurity = %+v, %v", sec, ok)
	}
}

func TestOperationParametersMergePathAndOperationLevel(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths:
  /users/{id}:
    parameters:
      - {name: id, in: path, schema: {type: string}}
    get:
      parameters:
        - {name: verbose, in: query, schema: {type: boolean}}
      responses: {"200": {description: ok}}
`))
	if err != nil {
		t.Fatal(err)
	}
	op := findOp(t, doc.Operations(), "get", "/users/{id}")
	if len(op.Parameters) != 2 {
		t.Fatalf("got %d parameters, want 2 (path-level id + operation-level verbose): %+v", len(op.Parameters), op.Parameters)
	}
	if !op.HasPathParameter() {
		t.Error("HasPathParameter() = false, want true")
	}
}

func TestOperationLevelParameterOverridesPathLevelOfTheSameNameAndLocation(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths:
  /users/{id}:
    parameters:
      - {name: id, in: path, schema: {type: string}}
    get:
      parameters:
        - {name: id, in: path, schema: {type: integer}}
      responses: {"200": {description: ok}}
`))
	if err != nil {
		t.Fatal(err)
	}
	op := findOp(t, doc.Operations(), "get", "/users/{id}")
	if len(op.Parameters) != 1 {
		t.Fatalf("got %d parameters, want 1 (operation-level override, not both): %+v", len(op.Parameters), op.Parameters)
	}
	if op.Parameters[0].Schema["type"] != "integer" {
		t.Errorf("got %+v, want the operation-level override's schema", op.Parameters[0])
	}
}

func TestRequestBodySchemaPrefersApplicationJSON(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths:
  /users:
    post:
      requestBody:
        content:
          application/xml: {schema: {type: string}}
          application/json: {schema: {type: object, properties: {name: {type: string}}}}
      responses: {"201": {description: created}}
`))
	if err != nil {
		t.Fatal(err)
	}
	op := findOp(t, doc.Operations(), "post", "/users")
	if op.RequestBody == nil {
		t.Fatal("RequestBody is nil")
	}
	if op.RequestBody["type"] != "object" {
		t.Errorf("got %+v, want the application/json schema", op.RequestBody)
	}
}

func TestResponsesCaptureEachStatusCodesSchemaOrNilIfUndocumented(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths:
  /users:
    get:
      responses:
        "200":
          content:
            application/json: {schema: {type: array, items: {type: object}}}
        "500":
          description: no schema documented
`))
	if err != nil {
		t.Fatal(err)
	}
	op := findOp(t, doc.Operations(), "get", "/users")
	if op.Responses["200"].Schema == nil {
		t.Error("200 response schema is nil, want the documented array schema")
	}
	if op.Responses["500"].Schema != nil {
		t.Errorf("500 response schema = %+v, want nil (no content documented)", op.Responses["500"].Schema)
	}
}
