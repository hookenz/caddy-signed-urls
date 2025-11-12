package signed

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Signed{})
}

type Signed struct {
	Secret string `json:"secret,omitempty"`
	logger *zap.Logger
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

func (s *Signed) Match(r *http.Request) bool {
	query := r.URL.Query()

	// Try both header and query param for signature
	sigStr := strings.TrimSpace(r.Header.Get("X-Signature"))
	if sigStr == "" {
		sigStr = strings.TrimSpace(query.Get("signature"))
	}

	if sigStr == "" {
		s.logger.Debug("no signature provided")
		return false
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		s.logger.Debug("signature decode failed", zap.Error(err))
		return false
	}

	expires := query.Get("expires")
	if expires != "" {
		expiresTime, err := strconv.ParseInt(expires, 10, 64)
		if err != nil {
			s.logger.Debug("invalid expires value", zap.String("expires", expires))
			return false
		}

		if time.Now().Unix() > expiresTime {
			s.logger.Debug("signature expired", zap.String("expires", expires))
			return false
		}
	}

	// Construct canonical URL for signing
	modifiedURL := *r.URL
	modifiedURL.Scheme = "http"
	if r.TLS != nil {
		modifiedURL.Scheme = "https"
	}
	modifiedURL.Host = r.Host

	q := modifiedURL.Query()
	q.Del("signature")
	modifiedURL.RawQuery = q.Encode() // ensures canonical order

	if !s.validateURL(modifiedURL.String(), sig) {
		s.logger.Debug("signature mismatch", zap.String("url", modifiedURL.String()))
		return false
	}

	return true
}

func (s *Signed) validateURL(targetUrl string, sig []byte) bool {
	h := hmac.New(sha256.New, []byte(s.Secret))
	h.Write([]byte(targetUrl))
	expectedSig := h.Sum(nil)
	return hmac.Equal(expectedSig, sig)
}

var (
	_ caddy.Provisioner        = (*Signed)(nil)
	_ caddy.Module             = (*Signed)(nil)
	_ caddyhttp.RequestMatcher = (*Signed)(nil)
	_ caddyfile.Unmarshaler    = (*Signed)(nil)
)
