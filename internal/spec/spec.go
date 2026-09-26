// Package spec parses an OpenAPI 3.x document (JSON or YAML) into a
// flat list of Operations, resolving local $ref pointers along the way
// so a rule never has to walk components.schemas itself. Only local
// refs (#/components/...) are resolved; a $ref into another file is
// left unresolved -- a real, stated limitation (docs/adr), not a
// silent wrong answer.
package spec

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Document is the whole parsed spec, kept as a generic map so any part
// of the document -- not just the pieces this package's own helpers
// know about -- stays reachable via ResolveRef.
type Document struct {
	raw map[string]any
}

// Parse decodes an OpenAPI document. YAML is tried first (a superset of
// JSON syntax for scalar and flow-mapping documents, so a JSON file
// still decodes correctly through the YAML parser); this avoids needing
// the caller to say which format a file is in.
func Parse(data []byte) (*Document, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("not valid YAML or JSON: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("empty document")
	}
	if _, ok := raw["openapi"]; !ok {
		return nil, fmt.Errorf(`not an OpenAPI 3.x document: missing top-level "openapi" field`)
	}
	normalizeMaps(raw)
	return &Document{raw: raw}, nil
}

// normalizeMaps rewrites every map[interface{}]interface{} (what
// gopkg.in/yaml.v3 produces for a YAML mapping under Go's map[string]any
// element type) into map[string]any recursively, so every consumer of a
// parsed Document can rely on one shape regardless of whether the
// source was JSON or YAML.
func normalizeMaps(v any) any {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			val[k] = normalizeMaps(child)
		}
		return val
	case []any:
		for i, child := range val {
			val[i] = normalizeMaps(child)
		}
		return val
	default:
		return v
	}
}

// ResolveRef follows a local JSON Reference (e.g.
// "#/components/schemas/User") from the document root. A ref into
// another file ("./other.yaml#/...") is not supported and returns
// false.
func (d *Document) ResolveRef(ref string) (map[string]any, bool) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	cur := any(d.raw)
	for _, segment := range strings.Split(ref[2:], "/") {
		segment = unescapeJSONPointer(segment)
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, ok := m[segment]
		if !ok {
			return nil, false
		}
		cur = next
	}
	result, ok := cur.(map[string]any)
	return result, ok
}

func unescapeJSONPointer(segment string) string {
	segment = strings.ReplaceAll(segment, "~1", "/")
	return strings.ReplaceAll(segment, "~0", "~")
}

// Resolve returns m itself, unless it is a {"$ref": "..."} object, in
// which case it follows the reference (once -- a ref chain is not
// supported, since OpenAPI documents in practice do not need one).
func (d *Document) Resolve(m map[string]any) map[string]any {
	if ref, ok := m["$ref"].(string); ok {
		if resolved, ok := d.ResolveRef(ref); ok {
			return resolved
		}
	}
	return m
}

// GlobalSecurity is the document's top-level "security" field, or nil
// if absent. An empty (but present) array is meaningfully different
// from an absent field: it means "no authentication is required by
// default," stated explicitly, not just never mentioned.
func (d *Document) GlobalSecurity() ([]any, bool) {
	return asOptionalList(d.raw["security"])
}

// SecurityScheme looks up a named scheme under components.securitySchemes.
func (d *Document) SecurityScheme(name string) (map[string]any, bool) {
	components, ok := d.raw["components"].(map[string]any)
	if !ok {
		return nil, false
	}
	schemes, ok := components["securitySchemes"].(map[string]any)
	if !ok {
		return nil, false
	}
	scheme, ok := schemes[name].(map[string]any)
	return scheme, ok
}

// Servers returns the document's top-level "servers" URLs.
func (d *Document) Servers() []string {
	rawServers, _ := d.raw["servers"].([]any)
	out := make([]string, 0, len(rawServers))
	for _, s := range rawServers {
		if sm, ok := s.(map[string]any); ok {
			if url, ok := sm["url"].(string); ok {
				out = append(out, url)
			}
		}
	}
	return out
}

// SecuritySchemeNames lists every scheme name defined under
// components.securitySchemes.
func (d *Document) SecuritySchemeNames() []string {
	components, ok := d.raw["components"].(map[string]any)
	if !ok {
		return nil
	}
	schemes, ok := components["securitySchemes"].(map[string]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(schemes))
	for name := range schemes {
		names = append(names, name)
	}
	return names
}

func asOptionalList(v any) ([]any, bool) {
	list, ok := v.([]any)
	return list, ok
}

// Property is one schema property, found anywhere in a schema (top
// level or nested inside an object property or an array's items).
type Property struct {
	Name   string
	Schema map[string]any
}

// MaxSchemaWalkDepth bounds WalkProperties' recursion so a
// self-referential schema (a "Comment" whose "replies" property is an
// array of "Comment") cannot recurse forever.
const MaxSchemaWalkDepth = 6

// WalkProperties finds every named property in schema, at any nesting
// depth, resolving $ref along the way -- this is how rules that check
// "is there a field named password anywhere in this response" see into
// nested objects and array item schemas, not just the top level.
func (d *Document) WalkProperties(schema map[string]any) []Property {
	var out []Property
	d.walkProperties(schema, MaxSchemaWalkDepth, &out)
	return out
}

func (d *Document) walkProperties(schema map[string]any, depth int, out *[]Property) {
	if depth <= 0 || schema == nil {
		return
	}
	schema = d.Resolve(schema)
	if props, ok := schema["properties"].(map[string]any); ok {
		for name, rawProp := range props {
			propSchema, ok := rawProp.(map[string]any)
			if !ok {
				continue
			}
			propSchema = d.Resolve(propSchema)
			*out = append(*out, Property{Name: name, Schema: propSchema})
			d.walkProperties(propSchema, depth-1, out)
			if items, ok := propSchema["items"].(map[string]any); ok {
				d.walkProperties(items, depth-1, out)
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		d.walkProperties(items, depth-1, out)
	}
}
