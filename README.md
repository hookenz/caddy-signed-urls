# Caddy Signed URL Plugin

A Caddy HTTP handler plugin that validates HMAC-SHA256 signed URLs. Perfect for creating time-limited, secure access to protected resources like file downloads, API endpoints, or any content that requires temporary authorization.

## Features

- 🔐 **HMAC-SHA256 signature verification** - Industry-standard cryptographic signing
- ⏰ **Optional expiration** - Create time-limited URLs that automatically expire
- 🎯 **Flexible configuration** - Support for query parameters and HTTP headers

## Installation

Build Caddy with this plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/hookenz/caddy-signed-urls
```

Or add it to your `go.mod`:

```bash
go get github.com/hookenz/caddy-signed-urls
```

## Quick Start

### Basic Usage

Protect file server routes with signed URLs:

```caddyfile
example.com {
    route /downloads/* {
        signed_url "your-secret-key"
        file_server {
            root /var/www/downloads
        }
    }
}
```

### With Expiration

Create URLs that expire after 1 hour:

```caddyfile
example.com {
    route /shared/* {
        signed_url "your-secret-key"
        file_server {
            root /var/www/shared
        }
    }
}
```

## Configuration

### Inline Syntax

```caddyfile
signed_url "your-secret-key"
```

### Block Syntax

```caddyfile
signed_url {
    secret "your-secret-key"       # Required
    algorithm "sha265"             # Optional, default: "sha256", options: sha265, sha384, sha512
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secret` | string | (required) | Secret key for HMAC signing |
| `algorithm` | string | `sha256` | The signature algorithm used by the signer |

## Generating Signed URLs

### Python

```python
import hmac
import hashlib
import time
from urllib.parse import urlencode

secret = "your-secret-key"
path = "/downloads/document.pdf"
issued = int(time.time())
expires = issued + 3600  # Valid for 1 hour

# Build query parameters (automatically sorted)
params = {
    'issued': issued,
    'expires': expires
}
query_string = urlencode(sorted(params.items()))

# Sign the path with sorted query parameters
to_sign = f"{path}?{query_string}"
signature = hmac.new(
    secret.encode(),
    to_sign.encode(),
    hashlib.sha256
).hexdigest()

# Final URL
url = f"{path}?{query_string}&signature={signature}"
print(url)
# /downloads/document.pdf?expires=1731632400&issued=1731628800&signature=abc123...
```

### Go

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "net/url"
    "time"
)

func generateSignedURL(secret, path string, ttl time.Duration) string {
    issued := time.Now().Unix()
    expires := issued + int64(ttl.Seconds())
    
    // Build query with sorted params
    query := url.Values{}
    query.Set("issued", fmt.Sprintf("%d", issued))
    query.Set("expires", fmt.Sprintf("%d", expires))
    
    // Sign the path with query params
    toSign := path + "?" + query.Encode()
    h := hmac.New(sha256.New, []byte(secret))
    h.Write([]byte(toSign))
    signature := hex.EncodeToString(h.Sum(nil))
    
    // Add signature to query
    query.Set("signature", signature)
    
    return path + "?" + query.Encode()
}

func main() {
    secret := "your-secret-key"
    path := "/downloads/document.pdf"
    url := generateSignedURL(secret, path, 1*time.Hour)
    fmt.Println(url)
}
```

### Node.js

```javascript
const crypto = require('crypto');

function generateSignedURL(secret, path, ttlSeconds) {
    const issued = Math.floor(Date.now() / 1000);
    const expires = issued + ttlSeconds;
    
    // Build query params (URLSearchParams sorts automatically)
    const params = new URLSearchParams();
    params.set('issued', issued);
    params.set('expires', expires);
    params.sort();
    
    // Sign the path with query params
    const toSign = `${path}?${params.toString()}`;
    const signature = crypto
        .createHmac('sha256', secret)
        .update(toSign)
        .digest('hex');
    
    // Add signature to query
    params.set('signature', signature);
    
    return `${path}?${params.toString()}`;
}

const url = generateSignedURL('your-secret-key', '/downloads/document.pdf', 3600);
console.log(url);
```

### PHP

```php
<?php

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function generateSignedURL($secret, $path, $ttl) {
    $issued = time();
    $expires = $issued + $ttl;

    // Build query params
    $params = [
        'expires' => $expires
    ];

    // Canonical order
    ksort($params);
    $queryString = http_build_query($params);

    // Message to sign
    $toSign = $path . '?' . $queryString;

    echo "toSign: $toSign\n";

    // HMAC-SHA256, binary output
    $hmac = hash_hmac('sha256', $toSign, $secret, true);

    // Base64-url without padding (matches Go RawURLEncoding)
    $signature = base64url_encode($hmac);

    // Add signature
    $params['signature'] = $signature;
    ksort($params);

    echo "path: $path\n";

    return $path . '?' . http_build_query($params);
}

$url generateSignedURL('secret', '/downloads/filename.jpg', 120);
echo $url
```

## Usage Examples

### Protecting File Downloads

```caddyfile
files.example.com {
    @downloads {
        path /downloads/*
        signed_url {
            secret "abc"
            algorithm "sha256"
        }
    }

    handle @downloads {
        file_server {
            root /var/www/downloads
        }

        respond "Forbidden" 403
    }
    
    # Public files don't need signing
    route /public/* {
        file_server {
            root /var/www/public-files
        }
    }
}
```

### Protecting API Endpoints

```caddyfile
api.example.com {
    route /api/private/* {
        signed_url "api-secret-key"
        reverse_proxy localhost:8080
    }
    
    route /api/public/* {
        reverse_proxy localhost:8080
    }
}
```

### Using Header-Based Signatures

For APIs where you don't want signatures in URLs:

```caddyfile
api.example.com {
    route /api/internal/* {
        signed_url {
            secret "internal-api-key"
        }
        reverse_proxy localhost:9000
    }
}
```

Client usage:
```bash
curl -H "X-Signature: abc123..." https://api.example.com/api/internal/data
```

## How It Works

### Signature Validation Process

1. **Extract signature** - Check query parameter or HTTP header
2. **Parse timestamps** - Validate `expires` if present
4. **Build signed string** - Reconstruct path + sorted query params (minus signature)
5. **Calculate HMAC** - Generate expected signature using secret key
6. **Compare** - Use constant-time comparison to prevent timing attacks
7. **Allow or deny** - Return 200 OK or 401 Unauthorized

### What Gets Signed

The signature covers:
- The full request path (e.g., `/downloads/file.pdf`)
- All query parameters except `signature` itself
- Query parameters must be sent in automatical order except `signature`

**Example:**
```
Original URL: /file?foo=bar&bar=buzz&expires=123
Signed URL: /file?foo=bar&bar=buzz&expires=123&signature=abcd...
```

## Security Considerations

### Secret Key Management

- **Use strong secrets** - Minimum 32 characters, randomly generated
- **Rotate regularly** - Change secrets periodically
- **Keep secrets secure** - Never commit to version control
- **Use environment variables** - Store secrets in environment or secret management systems

```caddyfile
{
    # Load secret from environment
    signed_url {
        secret {$SIGNED_URL_SECRET}
        algorithm {$SIGNED_URL_ALGORITHM}
    }
}
```

Suitable values for algorithm "sha256" (default if not specified), sha512"

### Expiration Times

- **Short TTLs recommended** - 1 hour or less for sensitive content
- **Balance security and usability** - Consider your use case
- **No default expiration** - Must explicitly set `expires` parameter

### HTTPS Required

Always use HTTPS in production to prevent signature interception:

```caddyfile
example.com {
    route /downloads/* {
        signed_url "secretkey"
        file_server
    }
}
```

## Logging

The plugin uses structured logging with different levels:

### INFO (Startup)
```json
{
  "level": "info",
  "logger": "http.handlers.signed_url",
  "msg": "signed_url handler provisioned",
  "query_param": "signature",
  "header": "X-Signature",
  "expires_param": "expires",
  "issued_param": "issued"
}
```

### WARN (Authentication Failures)
```json
{
  "level": "warn",
  "logger": "http.handlers.signed_url",
  "msg": "invalid signature",
  "path": "/downloads/file.pdf",
  "signature_source": "query",
  "remote_addr": "192.168.1.100:54321"
}
```

### DEBUG (Successful Validations)
```json
{
  "level": "debug",
  "logger": "http.handlers.signed_url",
  "msg": "signature validated successfully",
  "path": "/downloads/file.pdf",
  "signature_source": "query",
  "issued_at": 1731628800,
  "age_seconds": 450,
  "expires_at": 1731632400,
  "ttl_seconds": 3150
}
```

Enable debug logging:
```bash
caddy run --config Caddyfile --debug
```

Or in Caddyfile:
```caddyfile
{
    log {
        level DEBUG
    }
}
```

## Testing

Run the test suite:

```bash
# All tests
go test -v

# Specific test
go test -v -run TestSignedURL_QueryParamOrdering

# With coverage
go test -cover

# Benchmarks
go test -bench=.
```

## Error Responses

| Status Code | Message | Cause |
|------------|---------|-------|
| 400 Bad Request | Invalid expires parameter | Expires is not a valid Unix timestamp |
| 400 Bad Request | Invalid issued parameter | Issued is not a valid Unix timestamp |
| 401 Unauthorized | Missing signature | No signature in query param or header |
| 401 Unauthorized | Invalid signature | Signature verification failed |
| 401 Unauthorized | URL has expired | Current time is past expiration |


## Troubleshooting

### Common Issues

**1. "Invalid signature" errors**

- Check that the secret key matches on both sides
- Verify query parameters are sorted alphabetically when signing
- Ensure the path includes query parameters in the signature
- Check that signature is excluded from the signed string
- Check the format for the signature is url safe base64 defined in [RFC 4648 - Base 64 Encoding with URL and Filename Safe Alphabet](https://datatracker.ietf.org/doc/html/rfc4648#section-5)

**2. "URL has expired"**

- Verify system clocks are synchronized (use NTP)
- Check timezone is not affecting Unix timestamp generation
- Ensure TTL is appropriate for your use case

**3. "Missing signature"**

- Verify signature parameter name matches configuration
- Check if using header-based signatures, the header name is correct
- Ensure signature is being passed in the request

### Debug Tips

1. **Enable debug logging** to see successful validations
2. **Log the signed string** on both client and server
3. **Test with curl** to isolate client issues:

```bash
curl -v "https://example.com/file?expires=123&signature=abc"
```

4. **Use online HMAC calculators** to verify signature generation

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

[MIT License](LICENSE)

## Related Projects

- [Caddy](https://caddyserver.com/) - The web server this plugin extends
- [xcaddy](https://github.com/caddyserver/xcaddy) - Build tool for Caddy with plugins

## Support

- 📖 [Documentation](https://github.com/hookenz/caddy-signedurls)
- 🐛 [Issue Tracker](https://github.com/github.com/hookenz/caddy-signedurls/issues)
- 💬 [Caddy Community Forum](https://caddy.community/)

## Changelog

### v0.1.0
- Initial release
- HMAC-SHA256 signature validation
- Optional expiration support
- Issued timestamp for audit logging
- Query parameter and header support
- Test suite