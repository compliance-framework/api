package middleware

import "testing"

func TestGetTokenFromHeaderAcceptsCaseInsensitiveBearer(t *testing.T) {
	token, err := getTokenFromHeader("bearer token-value")
	if err != nil {
		t.Fatalf("expected lowercase bearer scheme to be accepted, got %v", err)
	}
	if token != "token-value" {
		t.Fatalf("expected token %q, got %q", "token-value", token)
	}
}
