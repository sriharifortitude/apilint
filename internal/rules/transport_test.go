package rules

import "testing"

func TestUnencryptedServerURL(t *testing.T) {
	bad := check(t, "unencrypted-server-url", docHeader+`
servers: [{url: "http://api.example.com"}]
paths: {}
`)
	if len(bad) != 1 {
		t.Fatalf("got %+v, want 1", bad)
	}

	https := check(t, "unencrypted-server-url", docHeader+`
servers: [{url: "https://api.example.com"}]
paths: {}
`)
	if len(https) != 0 {
		t.Fatalf("got %+v, want 0", https)
	}

	localhostIsExempt := check(t, "unencrypted-server-url", docHeader+`
servers: [{url: "http://localhost:3000"}]
paths: {}
`)
	if len(localhostIsExempt) != 0 {
		t.Fatalf("got %+v, want 0 (local dev server)", localhostIsExempt)
	}
}

func TestMissingRateLimitEvidence(t *testing.T) {
	bad := check(t, "missing-rate-limit-evidence", docHeader+`
paths:
  /users:
    get: {responses: {"200": {description: ok}}}
`)
	if len(bad) != 1 {
		t.Fatalf("got %+v, want 1", bad)
	}

	good := check(t, "missing-rate-limit-evidence", docHeader+`
paths:
  /users:
    get: {responses: {"200": {description: ok}, "429": {description: too many requests}}}
`)
	if len(good) != 0 {
		t.Fatalf("got %+v, want 0", good)
	}

	emptyDocumentIsNotFlagged := check(t, "missing-rate-limit-evidence", docHeader+"paths: {}\n")
	if len(emptyDocumentIsNotFlagged) != 0 {
		t.Fatalf("got %+v, want 0 (nothing to rate-limit yet)", emptyDocumentIsNotFlagged)
	}
}
