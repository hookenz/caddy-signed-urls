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

	"go.uber.org/zap"
)

func signURL(secret, rawURL string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(rawURL))
	sig := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sig)
}

func TestSigned_Match(t *testing.T) {
	secret := "secret"
	logger, _ := zap.NewDevelopment()
	signed := &Signed{
		Secret: secret,
		logger: logger,
	}

	baseURL := "https://example.com/private/file.txt"
	expires := time.Now().Add(10 * time.Minute).Unix()

	// Create canonical URL (without signature)
	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("expires", strconv.FormatInt(expires, 10))
	u.RawQuery = q.Encode()

	// Compute signature
	sig := signURL(secret, u.String())

	// Append signature to URL
	q.Set("signature", sig)
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{} // simulate https

	if !signed.Match(req) {
		t.Errorf("expected Match() to return true for valid signed URL")
	}
}

func TestSigned_Match_Expired(t *testing.T) {
	secret := "secret"
	logger, _ := zap.NewDevelopment()
	signed := &Signed{
		Secret: secret,
		logger: logger,
	}

	baseURL := "https://example.com/private/file.txt"
	expires := time.Now().Add(-1 * time.Minute).Unix()

	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("expires", strconv.FormatInt(expires, 10))
	u.RawQuery = q.Encode()

	sig := signURL(secret, u.String())

	q.Set("signature", sig)
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{}

	if signed.Match(req) {
		t.Errorf("expected Match() to return false for expired URL")
	}
}

func TestSigned_Match_InvalidSignature(t *testing.T) {
	secret := "secret"
	logger, _ := zap.NewDevelopment()
	signed := &Signed{
		Secret: secret,
		logger: logger,
	}

	baseURL := "https://example.com/private/file.txt"
	expires := time.Now().Add(10 * time.Minute).Unix()

	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("expires", strconv.FormatInt(expires, 10))
	u.RawQuery = q.Encode()

	// Wrong signature
	q.Set("signature", "invalidsig")
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{}

	if signed.Match(req) {
		t.Errorf("expected Match() to return false for invalid signature")
	}
}
