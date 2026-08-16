package signed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"io"
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

	signed := &SignedUrl{
		Secret: secret,
		logger: logger,
	}

	_ = signed.Provision(caddy.Context{})

	baseURL := "https://example.com/private/file.txt?z=last&b=first&a=second"
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

	signed := &SignedUrl{
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

	signed := &SignedUrl{
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

// helper: encrypt a plaintext token the same way the signing tool would
func encryptToken(t *testing.T, secret, plaintext string) string {
	t.Helper()
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext)
}

func generateCookieHash() (string, string, error) {
	// Generate a random binding value.
	bind := make([]byte, 10)
	if _, err := rand.Read(bind); err != nil {
		return "", "", err
	}

	// Encode the binding value for use in the URL.
	bindValue := base64.RawURLEncoding.EncodeToString(bind)

	// Hash the exact value that will appear in the URL.
	hash := sha256.Sum256([]byte(bindValue))

	// The URL gets the random value; the cookie gets its hash.
	return bindValue,
		base64.RawURLEncoding.EncodeToString(hash[:]),
		nil
}

// buildBoundSignedURL constructs a signed URL bound to a cookie value.
// It returns the URL and the cookie value that must accompany it.
func buildBoundSignedURL(t *testing.T, secret, baseURL string) (string, string) {
	t.Helper()

	bindValue, cookieValue, err := generateCookieHash()
	if err != nil {
		t.Fatal(err)
	}

	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("bind", bindValue)

	// Build canonical path + sorted query without signature.
	canonical := u.Path
	if encoded := q.Encode(); encoded != "" {
		canonical += "?" + encoded
	}

	sig := signCanonical(secret, canonical)

	// Append signature to query.
	q.Set("signature", sig)
	u.RawQuery = q.Encode()

	return u.String(), cookieValue
}

// TestSigned_MatchWithError_CookieToken_Valid tests that a request with a
// correctly encrypted token param and matching cookie passes.
func TestSigned_MatchWithError_CookieToken_Valid(t *testing.T) {
	secret := "secret"
	bindCookie := "su_secret"
	logger, _ := zap.NewDevelopment()

	signed := &SignedUrl{
		Secret:     secret,
		BindCookie: bindCookie,
		logger:     logger,
	}
	_ = signed.Provision(caddy.Context{})

	rawURL, cookieValue := buildBoundSignedURL(t, secret, "https://example.com/private/file.txt")

	logger.Info("Testing valid cookie-bound signed URL", zap.String("url", rawURL), zap.String("cookie", cookieValue))

	req, _ := http.NewRequest("GET", rawURL, nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: bindCookie, Value: cookieValue})

	ok, err := signed.MatchWithError(req)
	if err != nil || !ok {
		t.Fatalf("expected cookie-bound signed URL to pass, got ok=%v err=%v", ok, err)
	}
}

// TestSigned_MatchWithError_CookieToken_MissingCookie tests that the request
// is rejected when the cookie is absent even though the token param is valid.
func TestSigned_MatchWithError_CookieToken_MissingCookie(t *testing.T) {
	secret := "secret"
	bindCookie := "su_secret"
	logger, _ := zap.NewDevelopment()

	signed := &SignedUrl{
		Secret:     secret,
		BindCookie: bindCookie,
		logger:     logger,
	}
	_ = signed.Provision(caddy.Context{})

	rawURL, _ := buildBoundSignedURL(t, secret, "https://example.com/private/file.txt")

	req, _ := http.NewRequest("GET", rawURL, nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{}
	// deliberately no cookie added

	ok, err := signed.MatchWithError(req)
	if err == nil || ok {
		t.Fatalf("expected missing cookie to fail, got ok=%v err=%v", ok, err)
	}
}

// TestSigned_MatchWithError_CookieToken_WrongCookieValue tests that a request
// is rejected when the cookie value doesn't match the decrypted token.
func TestSigned_MatchWithError_CookieToken_WrongCookieValue(t *testing.T) {
	secret := "secret"
	bindCookie := "su_secret"
	logger, _ := zap.NewDevelopment()

	signed := &SignedUrl{
		Secret:     secret,
		BindCookie: bindCookie,
		logger:     logger,
	}
	_ = signed.Provision(caddy.Context{})

	rawURL, _ := buildBoundSignedURL(t, secret, "https://example.com/private/file.txt")

	req, _ := http.NewRequest("GET", rawURL, nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: bindCookie, Value: "wrong-value"})

	ok, err := signed.MatchWithError(req)
	if err == nil || ok {
		t.Fatalf("expected wrong cookie value to fail, got ok=%v err=%v", ok, err)
	}
}

// TestSigned_MatchWithError_CookieToken_TamperedToken tests that a request is
// rejected when the token param is replaced with a different valid ciphertext
// (i.e. someone re-encrypts a different value). The HMAC covers the token
// param, so swapping it invalidates the signature.
func TestSigned_MatchWithError_CookieToken_TamperedToken(t *testing.T) {
	secret := "secret"
	bindCookie := "su_secret"
	logger, _ := zap.NewDevelopment()

	signed := &SignedUrl{
		Secret:     secret,
		BindCookie: bindCookie,
		logger:     logger,
	}
	_ = signed.Provision(caddy.Context{})

	// Build a valid URL for "my-session-token"
	rawURL, _ := buildBoundSignedURL(t, secret, "https://example.com/private/file.txt")

	// Attacker replaces the token param with a fresh encryption of "attacker-value"
	// and sets the cookie to match — but the signature over the original token param
	// is now invalid.
	tamperedToken := encryptToken(t, secret, "attacker-value")
	u, _ := url.Parse(rawURL)
	q := u.Query()
	q.Set("token", tamperedToken)
	u.RawQuery = q.Encode()

	req, _ := http.NewRequest("GET", u.String(), nil)
	req.Host = "example.com"
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: bindCookie, Value: "attacker-value"})

	ok, err := signed.MatchWithError(req)
	if err == nil || ok {
		t.Fatalf("expected tampered token to fail signature check, got ok=%v err=%v", ok, err)
	}
}
