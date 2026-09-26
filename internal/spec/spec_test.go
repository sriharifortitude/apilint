package spec

import (
	"testing"
	"time"
)

func timeoutAfter() <-chan time.Time {
	return time.After(2 * time.Second)
}

const minimalDoc = `
openapi: 3.0.3
info: {title: test, version: "1.0"}
paths: {}
`

func TestParseRejectsNonOpenAPIInput(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"not yaml or json", "{{{not valid"},
		{"missing openapi field", `info: {title: x, version: "1"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse([]byte(c.data)); err == nil {
				t.Fatalf("Parse(%q) succeeded, want an error", c.data)
			}
		})
	}
}

func TestParseAcceptsAMinimalDocument(t *testing.T) {
	doc, err := Parse([]byte(minimalDoc))
	if err != nil {
		t.Fatal(err)
	}
	if doc == nil {
		t.Fatal("got nil document")
	}
}

func TestParseAcceptsJSONToo(t *testing.T) {
	json := `{"openapi": "3.0.3", "info": {"title": "x", "version": "1"}, "paths": {}}`
	if _, err := Parse([]byte(json)); err != nil {
		t.Fatal(err)
	}
}

func TestResolveRefFollowsALocalPointer(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths: {}
components:
  schemas:
    User:
      type: object
      properties:
        id: {type: string}
`))
	if err != nil {
		t.Fatal(err)
	}
	resolved, ok := doc.ResolveRef("#/components/schemas/User")
	if !ok {
		t.Fatal("ResolveRef returned false")
	}
	if resolved["type"] != "object" {
		t.Errorf("resolved = %+v, want type: object", resolved)
	}
}

func TestResolveRefReturnsFalseForANonLocalRef(t *testing.T) {
	doc, _ := Parse([]byte(minimalDoc))
	if _, ok := doc.ResolveRef("./other.yaml#/components/schemas/User"); ok {
		t.Fatal("expected false for a non-local ref")
	}
}

func TestResolveRefReturnsFalseForAMissingPath(t *testing.T) {
	doc, _ := Parse([]byte(minimalDoc))
	if _, ok := doc.ResolveRef("#/components/schemas/DoesNotExist"); ok {
		t.Fatal("expected false for a missing path")
	}
}

func TestGlobalSecurityDistinguishesAbsentFromExplicitlyEmpty(t *testing.T) {
	noSecurity, _ := Parse([]byte(minimalDoc))
	if _, ok := noSecurity.GlobalSecurity(); ok {
		t.Error("expected no global security field to report ok=false")
	}

	explicitEmpty, _ := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths: {}
security: []
`))
	sec, ok := explicitEmpty.GlobalSecurity()
	if !ok {
		t.Fatal("expected an explicit empty security array to report ok=true")
	}
	if len(sec) != 0 {
		t.Errorf("got %+v, want an empty slice", sec)
	}
}

func TestSecuritySchemeLooksUpByName(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths: {}
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
`))
	if err != nil {
		t.Fatal(err)
	}
	scheme, ok := doc.SecurityScheme("bearerAuth")
	if !ok {
		t.Fatal("expected to find bearerAuth")
	}
	if scheme["scheme"] != "bearer" {
		t.Errorf("got %+v", scheme)
	}
	if _, ok := doc.SecurityScheme("doesNotExist"); ok {
		t.Error("expected not to find an undeclared scheme")
	}
}

func TestWalkPropertiesFindsNestedAndArrayItemProperties(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths: {}
components:
  schemas:
    User:
      type: object
      properties:
        id: {type: string}
        profile:
          type: object
          properties:
            bio: {type: string}
        tags:
          type: array
          items:
            type: object
            properties:
              label: {type: string}
`))
	if err != nil {
		t.Fatal(err)
	}
	schema, _ := doc.ResolveRef("#/components/schemas/User")
	props := doc.WalkProperties(schema)

	names := map[string]bool{}
	for _, p := range props {
		names[p.Name] = true
	}
	for _, want := range []string{"id", "profile", "bio", "tags", "label"} {
		if !names[want] {
			t.Errorf("WalkProperties missed %q, got %+v", want, names)
		}
	}
}

func TestWalkPropertiesResolvesRefsAtEveryLevel(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths: {}
components:
  schemas:
    Address: {type: object, properties: {city: {type: string}}}
    User:
      type: object
      properties:
        address: {$ref: "#/components/schemas/Address"}
`))
	if err != nil {
		t.Fatal(err)
	}
	schema, _ := doc.ResolveRef("#/components/schemas/User")
	props := doc.WalkProperties(schema)
	var sawCity bool
	for _, p := range props {
		if p.Name == "city" {
			sawCity = true
		}
	}
	if !sawCity {
		t.Errorf("expected to find city through the $ref, got %+v", props)
	}
}

func TestWalkPropertiesDoesNotRecurseForeverOnASelfReferentialSchema(t *testing.T) {
	doc, err := Parse([]byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
paths: {}
components:
  schemas:
    Comment:
      type: object
      properties:
        text: {type: string}
        replies:
          type: array
          items: {$ref: "#/components/schemas/Comment"}
`))
	if err != nil {
		t.Fatal(err)
	}
	schema, _ := doc.ResolveRef("#/components/schemas/Comment")
	done := make(chan []Property, 1)
	go func() { done <- doc.WalkProperties(schema) }()
	select {
	case props := <-done:
		if len(props) == 0 {
			t.Fatal("expected at least the top-level properties")
		}
	case <-timeoutAfter():
		t.Fatal("WalkProperties did not terminate on a self-referential schema")
	}
}
