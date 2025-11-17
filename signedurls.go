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
	_ caddy.Provisioner                 = (*Signed)(nil)
	_ caddy.Module                      = (*Signed)(nil)
	_ caddyhttp.RequestMatcherWithError = (*Signed)(nil)
	_ caddyfile.Unmarshaler             = (*Signed)(nil)
)

func init() {
	caddy.RegisterModule(Signed{})
}

type Signed struct {
	Secret    string `json:"secret,omitempty"`
	Algorithm string `json:"algorithm,omitempty"`

	hashFunc func() hash.Hash
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Signed) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.signed",
		New: func() caddy.Module { return new(Signed) },
	}
}

func (s *Signed) Provision(ctx caddy.Context) error {
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

func (s *Signed) Validate() error {
	if s.Secret == "" {
		return fmt.Errorf("secret is required")
	}
	return nil
}

func (s *Signed) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 1:
			s.Secret = args[0]
		default:
			return d.Err("unexpected number of arguments")
		}
	}
	return nil
}

func (s *Signed) MatchWithError(r *http.Request) (bool, error) {
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

	// Construct canonical URL for signing
	// Build canonical path+query string
	q := r.URL.Query()
	q.Del("signature")

	canonical := r.URL.Path
	encoded := q.Encode()

	if encoded != "" {
		canonical += "?" + encoded
	}

	if !s.validateURL(canonical, sig) {
		s.logger.Debug("signature mismatch", zap.String("url", canonical))
		return false, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("signature"))
	}

	return true, nil
}

func (s *Signed) validateURL(targetUrl string, sig []byte) bool {
	h := hmac.New(s.hashFunc, []byte(s.Secret))
	h.Write([]byte(targetUrl))
	expectedSig := h.Sum(nil)
	return hmac.Equal(expectedSig, sig)
}
