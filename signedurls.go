package signed

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"net/http"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

var (
	_ caddy.Provisioner                 = (*SignedUrl)(nil)
	_ caddy.Module                      = (*SignedUrl)(nil)
	_ caddyhttp.RequestMatcherWithError = (*SignedUrl)(nil)
	_ caddyfile.Unmarshaler             = (*SignedUrl)(nil)
)

func init() {
	caddy.RegisterModule(SignedUrl{})
}

type SignedUrl struct {
	Secret    string `json:"secret,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`

	hashFunc func() hash.Hash
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SignedUrl) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.signed_url",
		New: func() caddy.Module { return new(SignedUrl) },
	}
}

func (s *SignedUrl) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger()

	// Set hash function
	switch s.Algorithm {
	case "", "sha256":
		s.hashFunc = sha256.New
	case "sha384":
		s.hashFunc = sha512.New384
	case "sha512":
		s.hashFunc = sha512.New
	default:
		return fmt.Errorf("unsupported algorithm: %s", s.Algorithm)
	}

	return nil
}

func (s *SignedUrl) Validate() error {
	if s.Secret == "" {
		return fmt.Errorf("secret is required")
	}
	return nil
}

// UnmarshalCaddyfile parses the signed_url directive.
// It url signing and configures it with this syntax:
//
//	signed_url [<matcher>] [secret-key] {
//	    secret        <secret-key>
//	    algorithm     <alg>
//	}
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

		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

func (s *SignedUrl) MatchWithError(r *http.Request) (bool, error) {
	query := r.URL.Query()

	s.logger.Info("MatchWithError called",
		zap.String("path", r.URL.Path),
		zap.Any("query", query),
	)

	sigStr := r.URL.Query().Get("signature")
	if sigStr == "" {
		sigStr = r.Header.Get("X-Signature")
	}
	if sigStr == "" {
		s.logger.Warn("missing signature", zap.String("path", r.URL.Path))
		return false, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("missing signature"))
	}

	s.logger.Debug("Signature:", zap.String("sigStr", sigStr))

	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		s.logger.Debug("signature decode failed", zap.Error(err))
		return false, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid signature encoding"))
	}

	// Check expiration
	now := time.Now().Unix()
	expStr := r.URL.Query().Get("expires")
	if expStr != "" {
		exp, err := strconv.ParseInt(expStr, 10, 64)
		if err != nil {
			return false, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid expires param"))
		}
		if now > exp {
			return false, caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("URL expired"))
		}
	}

	q := r.URL.Query()
	q.Del("signature")

	canonical := r.URL.Path
	encoded := q.Encode()

	if encoded != "" {
		canonical += "?" + encoded
	}

	if !s.verifySignature(canonical, sig) {
		s.logger.Debug("signature mismatch", zap.String("url", canonical))
		return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("signature"))
	}

	return true, nil
}

func (s *SignedUrl) verifySignature(input string, sig []byte) bool {
	h := hmac.New(s.hashFunc, []byte(s.Secret))
	h.Write([]byte(input))
	expectedSig := h.Sum(nil)
	return hmac.Equal(expectedSig, sig)
}
