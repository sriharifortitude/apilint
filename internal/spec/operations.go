package spec

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// Parameter is one path/query/header/cookie parameter, with its schema
// already resolved through any $ref.
type Parameter struct {
	Name   string
	In     string
	Schema map[string]any
}

// ResponseInfo is one status code's documented response.
type ResponseInfo struct {
	// Schema is nil when the response declares no content/schema at
	// all -- itself worth a rule flagging, not something to paper over
	// with an empty map (see rules.MissingResponseSchema).
	Schema map[string]any
}

// Operation is one (method, path) pair, with every field this package's
// rules need already resolved: parameters merged from the path item and
// the operation itself, $refs followed, and security's absent-vs-empty
// distinction preserved explicitly rather than collapsed to one zero
// value.
type Operation struct {
	Method      string
	Path        string
	OperationID string
	Parameters  []Parameter
	// HasOwnSecurity is true when this operation has its own "security"
	// field at all, even if it's an empty array (meaning "explicitly no
	// auth required" -- a deliberate choice, unlike simply never
	// mentioning it).
	HasOwnSecurity bool
	OwnSecurity    []any
	RequestBody    map[string]any // resolved schema, nil if no request body is documented
	Responses      map[string]ResponseInfo
}

// EffectiveSecurity is what actually applies to this operation: its own
// security field if it has one (including an explicit empty array),
// otherwise the document's global default.
func (o Operation) EffectiveSecurity(doc *Document) ([]any, bool) {
	if o.HasOwnSecurity {
		return o.OwnSecurity, true
	}
	return doc.GlobalSecurity()
}

// HasPathParameter reports whether this operation's path contains a
// templated segment ({id}, {userId}, ...) -- the shape that makes a
// missing authorization check a BOLA/IDOR risk specifically, not just a
// generically open endpoint.
func (o Operation) HasPathParameter() bool {
	for _, p := range o.Parameters {
		if p.In == "path" {
			return true
		}
	}
	return false
}

// Operations walks every path and method in the document, returning one
// flattened Operation per (method, path) pair that has an operation
// object.
func (d *Document) Operations() []Operation {
	paths, ok := d.raw["paths"].(map[string]any)
	if !ok {
		return nil
	}

	var ops []Operation
	for path, rawItem := range paths {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		pathLevelParams := d.parameters(item)

		for _, method := range httpMethods {
			rawOp, ok := item[method].(map[string]any)
			if !ok {
				continue
			}
			opParams := d.parameters(rawOp)
			opID, _ := rawOp["operationId"].(string)

			security, hasSecurity := asOptionalList(rawOp["security"])

			ops = append(ops, Operation{
				Method:         method,
				Path:           path,
				OperationID:    opID,
				Parameters:     mergeParameters(pathLevelParams, opParams),
				HasOwnSecurity: hasSecurity,
				OwnSecurity:    security,
				RequestBody:    d.requestBodySchema(rawOp),
				Responses:      d.responses(rawOp),
			})
		}
	}
	return ops
}

func (d *Document) parameters(holder map[string]any) []Parameter {
	rawParams, _ := holder["parameters"].([]any)
	out := make([]Parameter, 0, len(rawParams))
	for _, rp := range rawParams {
		pm, ok := rp.(map[string]any)
		if !ok {
			continue
		}
		pm = d.Resolve(pm)
		name, _ := pm["name"].(string)
		in, _ := pm["in"].(string)
		schema, _ := pm["schema"].(map[string]any)
		out = append(out, Parameter{Name: name, In: in, Schema: d.Resolve(schema)})
	}
	return out
}

// mergeParameters combines a path item's shared parameters with an
// operation's own, letting an operation-level parameter of the same
// (name, in) override the path-level one -- the same override rule the
// OpenAPI spec itself defines.
func mergeParameters(pathLevel, opLevel []Parameter) []Parameter {
	byKey := make(map[[2]string]Parameter, len(pathLevel)+len(opLevel))
	var order [][2]string
	for _, p := range pathLevel {
		key := [2]string{p.Name, p.In}
		if _, exists := byKey[key]; !exists {
			order = append(order, key)
		}
		byKey[key] = p
	}
	for _, p := range opLevel {
		key := [2]string{p.Name, p.In}
		if _, exists := byKey[key]; !exists {
			order = append(order, key)
		}
		byKey[key] = p
	}
	out := make([]Parameter, 0, len(order))
	for _, key := range order {
		out = append(out, byKey[key])
	}
	return out
}

func (d *Document) requestBodySchema(rawOp map[string]any) map[string]any {
	rb, ok := rawOp["requestBody"].(map[string]any)
	if !ok {
		return nil
	}
	rb = d.Resolve(rb)
	return d.schemaFromContent(rb)
}

func (d *Document) responses(rawOp map[string]any) map[string]ResponseInfo {
	rawResponses, ok := rawOp["responses"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]ResponseInfo, len(rawResponses))
	for status, rr := range rawResponses {
		rm, ok := rr.(map[string]any)
		if !ok {
			continue
		}
		rm = d.Resolve(rm)
		out[status] = ResponseInfo{Schema: d.schemaFromContent(rm)}
	}
	return out
}

// schemaFromContent reads content.<media-type>.schema, preferring
// application/json when multiple media types are documented, and
// resolves the schema through any $ref.
func (d *Document) schemaFromContent(holder map[string]any) map[string]any {
	content, ok := holder["content"].(map[string]any)
	if !ok {
		return nil
	}
	mediaType, ok := content["application/json"].(map[string]any)
	if !ok {
		for _, v := range content {
			if mt, ok := v.(map[string]any); ok {
				mediaType = mt
				break
			}
		}
	}
	if mediaType == nil {
		return nil
	}
	schema, ok := mediaType["schema"].(map[string]any)
	if !ok {
		return nil
	}
	return d.Resolve(schema)
}
