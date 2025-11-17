package signed

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// Helper: sign canonical path+query (not full URL)
func signCanonical(secret, canonical string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func TestSigned_MatchWithError(t *testing.T) {
	secret := "secret"
	logger, _ := zap.NewDevelopment()

	signed := &Signed{
		Secret: secret,
		logger: logger,
	}

	_ = signed.Provision(caddy.Context{})

	baseURL := "https://example.com/private/file.txt"
	expires := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)

	// Build URL (signature added later)
	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("expires", expires)
	u.RawQuery = q.Encode()

	// Canonical string for signing
	canonical := u.Path + "?" + u.RawQuery

	// Compute signature
	sig := signCanonical(secret, canonical)

	// Add signature to request URL
	q.Set("signature", sig)
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{}

	ok, err := signed.MatchWithError(req)
	if err != nil || !ok {
		t.Fatalf("expected MatchWithError() ok=true, got ok=%v err=%v", ok, err)
	}
}

func TestSigned_MatchWithError_Expired(t *testing.T) {
	secret := "secret"
	logger, _ := zap.NewDevelopment()

	signed := &Signed{
		Secret: secret,
		logger: logger,
	}
	_ = signed.Provision(caddy.Context{})

	baseURL := "https://example.com/private/file.txt"
	expires := strconv.FormatInt(time.Now().Add(-1*time.Minute).Unix(), 10)

	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("expires", expires)
	u.RawQuery = q.Encode()

	// canonical string
	canonical := u.Path + "?" + u.RawQuery
	sig := signCanonical(secret, canonical)

	// add signature
	q.Set("signature", sig)
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{}

	ok, err := signed.MatchWithError(req)
	if err == nil || ok {
		t.Fatalf("expected expired URL to fail, got ok=%v err=%v", ok, err)
	}
}

func TestSigned_MatchWithError_InvalidSignature(t *testing.T) {
	secret := "secret"
	logger, _ := zap.NewDevelopment()

	signed := &Signed{
		Secret: secret,
		logger: logger,
	}
	_ = signed.Provision(caddy.Context{})

	baseURL := "https://example.com/private/file.txt"
	expires := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)

	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("expires", expires)
	u.RawQuery = q.Encode()

	// wrong signature
	q.Set("signature", "bogus")
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{}

	ok, err := signed.MatchWithError(req)
	if err == nil || ok {
		t.Fatalf("expected invalid signature error, got ok=%v err=%v", ok, err)
	}
}
