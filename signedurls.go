package signed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"slices"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SignedUrl{})
}

// SignedUrl is a Caddy request matcher that validates signed URLs using HMAC signatures.
//
// The signature is expected to be provided as a query parameter named "signature"
// or as an "X-Signature" header. The URL is considered valid if the signature
// matches the expected value computed using the secret key and the canonical
// URL (path + query string without the signature).
//
// Optionally, an "expires" query parameter can be included to specify a Unix
// timestamp after which the URL is no longer valid.
//
// The signature should be encoded using base64 URL encoding without padding.
type SignedUrl struct {
	// The secret key used to sign URLs. This should be a strong, random string.
	Secret string `json:"secret,omitempty"`

	// The hash algorithm to use for signing. Supported values: "sha256" (default), "sha384", "sha512".
	Algorithm string `json:"algorithm,omitempty"`

	// CookieName enables cookie-bound token verification when set.
	// The URL must carry an "token" query param containing an AES-GCM
	// encrypted value that, once decrypted, must match this cookie's value.
	CookieName string `json:"cookie_name,omitempty"`

	aesKey   []byte // 32-byte AES-256 key derived from Secret
	logger   *zap.Logger
}

var validHashAlg = []string{"", "sha256", "sha384", "sha512"}

// CaddyModule returns the Caddy module information.
func (SignedUrl) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.signed_url",
		New: func() caddy.Module { return new(SignedUrl) },
	}
}

func (s *SignedUrl) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()

	if slices.Contains(validHashAlg, s.Algorithm) {
		return fmt.Errorf("unsupported hash algorithm: %s", s.Algorithm)
	}

	// Derive a 32-byte AES key from the secret using SHA-256.
	// This is done at provision time so it's not repeated per-request.
	if s.CookieName != "" {
		h := sha256.Sum256([]byte(s.Secret))
		s.aesKey = h[:]
	}

	return nil
}

func (s *SignedUrl) Validate() error {
	s.logger.Debug("settings",
		zap.String("secret", s.Secret),
		zap.String("alg", s.Algorithm),
		zap.String("cookie_name", s.CookieName),
	)
	return nil
}

func (s *SignedUrl) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	// --- handle single-line shorthand: signed_url "secret" ---
	args := d.RemainingArgs()
	if len(args) == 1 {
		s.Secret = args[0]
	} else if len(args) > 1 {
		return d.ArgErr()
	}

	// --- handle block options ---
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			if s.Secret != "" {
				return d.Err("secret already configured")
			}
			s.Secret = d.Val()
		case "algorithm":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.Algorithm = d.Val()
		case "cookie_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			s.CookieName = d.Val()
		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}
	return nil
}

func (s *SignedUrl) Match(r *http.Request) bool {
	match, err := s.MatchWithError(r)
	if err != nil {
		s.logger.Error("failed to validate signed URL", zap.Error(err))
	}

	return match
}

func (s *SignedUrl) MatchWithError(r *http.Request) (bool, error) {
	query := r.URL.Query()

	s.logger.Info("MatchWithError called",
		zap.String("path", r.URL.Path),
		zap.Any("query", query),
	)

	sigStr := query.Get("signature")
	if sigStr == "" {
		sigStr = r.Header.Get("X-Signature")
	}
	if sigStr == "" {
		s.logger.Warn("Missing signature", zap.String("path", r.URL.Path))
		return false, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("missing signature"))
	}

	s.logger.Debug("Signature", zap.String("sigStr", sigStr))

	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		s.logger.Debug("signature decode failed", zap.Error(err))
		return false, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid signature encoding"))
	}

	// Construct canonical URL for signing
	// Build canonical path+query string
	q := r.URL.Query()
	q.Del("signature")

	// Check expiration before anything else
	expStr := query.Get("expires")
	if expStr != "" {
		exp, err := strconv.ParseInt(expStr, 10, 64)
		if err != nil {
			return false, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid expires param"))
		}
		if time.Now().Unix() > exp {
			s.logger.Warn("URL expired", zap.String("path", r.URL.Path))
			return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("URL expired"))
		}
	}

	// Build canonical URL for HMAC verification (excludes signature param)
	canonical := r.URL.Path
	if encoded := q.Encode(); encoded != "" {
		canonical += "?" + encoded
	}

	secret := replacePlaceholders(r, s.Secret)
	if secret == "" {
		return false, caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("resolved secret is empty"))
	}

	if !s.verifySignature(secret, canonical, sig) {
		s.logger.Debug("signature mismatch", zap.String("url", canonical))
		return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("signature mismatch"))
	}

	// Cookie-bound token verification (opt-in)
	if s.CookieName != "" {
		if ok, err := s.verifyCookieToken(r, query); !ok {
			s.logger.Debug("cookie mismatch", zap.String("url", canonical))
			return false, err
		}
	}

	return true, nil
}

// verifyCookieToken decrypts the "token" query param and compares it to the
// named cookie value. Both must be present and match.
func (s *SignedUrl) verifyCookieToken(r *http.Request, query map[string][]string) (bool, error) {
	tokenParam := ""
	if vals, ok := query["token"]; ok && len(vals) > 0 {
		tokenParam = vals[0]
	}

	if tokenParam == "" {
		s.logger.Warn("cookie-bound check: missing token param")
		return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("missing token param"))
	}

	cookie, err := r.Cookie(s.CookieName)
	if err != nil {
		s.logger.Warn("cookie-bound check: missing cookie", zap.String("cookie", s.CookieName))
		return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("missing cookie"))
	}

	// Decrypt the token param
	ciphertext, err := base64.RawURLEncoding.DecodeString(tokenParam)
	if err != nil {
		return false, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid token encoding"))
	}

	plaintext, err := aesGCMDecrypt(s.aesKey, ciphertext)
	if err != nil {
		s.logger.Warn("cookie-bound check: token decryption failed", zap.Error(err))
		return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("invalid token"))
	}

	if !hmac.Equal(plaintext, []byte(cookie.Value)) {
		s.logger.Warn("cookie-bound check: token/cookie mismatch")
		return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("token/cookie mismatch"))
	}

	return true, nil
}

// aesGCMDecrypt decrypts data encrypted with AES-256-GCM.
// Ciphertext format: [12-byte nonce][ciphertext+tag]
func aesGCMDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize() // 12
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (s *SignedUrl) verifySignature(secret, input string, sig []byte) bool {

	hashFunc := sha256.New
	switch s.Algorithm {
	case "sha256":
		hashFunc = sha256.New
	case "sha384":
		hashFunc = sha512.New384
	case "sha512":
		hashFunc = sha512.New
	}

	h := hmac.New(hashFunc, []byte(secret))
	h.Write([]byte(input))
	expected := h.Sum(nil)
	s.logger.Debug("verifying signature",
		zap.String("input", input),
		zap.String("expected", base64.RawURLEncoding.EncodeToString(expected)),
	)
	return hmac.Equal(sig, expected)
}

func replacePlaceholders(r *http.Request, value string) string {
	repl := r.Context().Value(caddy.ReplacerCtxKey)
	if repl == nil {
		return value
	}
	replacer, ok := repl.(*caddy.Replacer)
	if !ok {
		return value
	}
	return replacer.ReplaceAll(value, "")
}

var (
	_ caddy.Provisioner                 = (*SignedUrl)(nil)
	_ caddy.Module                      = (*SignedUrl)(nil)
	_ caddyhttp.RequestMatcher          = (*SignedUrl)(nil)
	_ caddyhttp.RequestMatcherWithError = (*SignedUrl)(nil)
	_ caddyfile.Unmarshaler             = (*SignedUrl)(nil)
)
