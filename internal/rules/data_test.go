package rules

import "testing"

func TestSensitiveFieldInResponse(t *testing.T) {
	bad := check(t, "sensitive-field-in-response", docHeader+`
paths:
  /users/{id}:
    get:
      responses:
        "200":
          content:
            application/json:
              schema:
                type: object
                properties:
                  id: {type: string}
                  password: {type: string}
`)
	if len(bad) != 1 {
		t.Fatalf("got %+v, want 1", bad)
	}

	writeOnlyIsFine := check(t, "sensitive-field-in-response", docHeader+`
paths:
  /users:
    post:
      responses:
        "201":
          content:
            application/json:
              schema:
                type: object
                properties:
                  password: {type: string, writeOnly: true}
`)
	if len(writeOnlyIsFine) != 0 {
		t.Fatalf("got %+v, want 0 (writeOnly means it never actually appears)", writeOnlyIsFine)
	}

	notAResponseField := check(t, "sensitive-field-in-response", docHeader+`
paths:
  /users:
    get:
      responses:
        "200":
          content:
            application/json:
              schema: {type: object, properties: {name: {type: string}}}
`)
	if len(notAResponseField) != 0 {
		t.Fatalf("got %+v, want 0", notAResponseField)
	}

	nestedFieldIsFound := check(t, "sensitive-field-in-response", docHeader+`
paths:
  /users:
    get:
      responses:
        "200":
          content:
            application/json:
              schema:
                type: object
                properties:
                  account:
                    type: object
                    properties:
                      apiKey: {type: string}
`)
	if len(nestedFieldIsFound) != 1 {
		t.Fatalf("got %+v, want 1 (nested apiKey field)", nestedFieldIsFound)
	}
}

func TestMassAssignmentRisk(t *testing.T) {
	bad := check(t, "mass-assignment-risk", docHeader+`
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema: {type: object, properties: {name: {type: string}, role: {type: string}}}
      responses: {"201": {description: created}}
`)
	if len(bad) != 1 {
		t.Fatalf("got %+v, want 1 (role)", bad)
	}

	idOnCreateIsFlagged := check(t, "mass-assignment-risk", docHeader+`
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema: {type: object, properties: {id: {type: string}, name: {type: string}}}
      responses: {"201": {description: created}}
`)
	if len(idOnCreateIsFlagged) != 1 {
		t.Fatalf("got %+v, want 1 (client-chosen id on create)", idOnCreateIsFlagged)
	}

	idOnUpdateIsFine := check(t, "mass-assignment-risk", docHeader+`
paths:
  /users/{id}:
    put:
      requestBody:
        content:
          application/json:
            schema: {type: object, properties: {id: {type: string}, name: {type: string}}}
      responses: {"200": {description: ok}}
`)
	if len(idOnUpdateIsFine) != 0 {
		t.Fatalf("got %+v, want 0 (id in a PUT body targeting an already-identified resource is normal)", idOnUpdateIsFine)
	}

	getIsNeverChecked := check(t, "mass-assignment-risk", docHeader+`
paths:
  /users:
    get:
      responses: {"200": {description: ok}}
`)
	if len(getIsNeverChecked) != 0 {
		t.Fatalf("got %+v, want 0 (GET has no request body)", getIsNeverChecked)
	}
}

func TestMissingFormatConstraint(t *testing.T) {
	bad := check(t, "missing-format-constraint", docHeader+`
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema: {type: object, properties: {email: {type: string}}}
      responses: {"201": {description: created}}
`)
	if len(bad) != 1 {
		t.Fatalf("got %+v, want 1", bad)
	}

	withFormat := check(t, "missing-format-constraint", docHeader+`
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema: {type: object, properties: {email: {type: string, format: email}}}
      responses: {"201": {description: created}}
`)
	if len(withFormat) != 0 {
		t.Fatalf("got %+v, want 0", withFormat)
	}

	unrelatedFieldName := check(t, "missing-format-constraint", docHeader+`
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema: {type: object, properties: {name: {type: string}}}
      responses: {"201": {description: created}}
`)
	if len(unrelatedFieldName) != 0 {
		t.Fatalf("got %+v, want 0", unrelatedFieldName)
	}
}

func TestMissingResponseSchema(t *testing.T) {
	bad := check(t, "missing-response-schema", docHeader+`
paths:
  /users:
    get:
      responses:
        "200": {description: "ok, but no schema"}
`)
	if len(bad) != 1 {
		t.Fatalf("got %+v, want 1", bad)
	}

	good := check(t, "missing-response-schema", docHeader+`
paths:
  /users:
    get:
      responses:
        "200":
          content:
            application/json: {schema: {type: array, items: {type: object}}}
`)
	if len(good) != 0 {
		t.Fatalf("got %+v, want 0", good)
	}

	noContentIsExempt := check(t, "missing-response-schema", docHeader+`
paths:
  /users/{id}:
    delete:
      responses:
        "204": {description: "deleted, no body"}
`)
	if len(noContentIsExempt) != 0 {
		t.Fatalf("got %+v, want 0 (204 legitimately has no body)", noContentIsExempt)
	}

	errorResponsesAreNotChecked := check(t, "missing-response-schema", docHeader+`
paths:
  /users:
    get:
      responses:
        "200": {content: {application/json: {schema: {type: array, items: {type: object}}}}}
        "500": {description: "no schema, and that's fine -- only 2xx is checked"}
`)
	if len(errorResponsesAreNotChecked) != 0 {
		t.Fatalf("got %+v, want 0", errorResponsesAreNotChecked)
	}
}
