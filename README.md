# Caddy Signed URL Plugin

A Caddy HTTP handler plugin that validates HMAC-signed URLs. Perfect for creating secure access to protected resources like file downloads or API endpoints.

## Features

- 🔐 **HMAC signature verification** – Industry-standard cryptographic signing  
- 🎯 **Flexible algorithm choice** – Supports multiple HMAC algorithms  
- 🔗 **URL-safe signatures** – Uses raw URL-safe Base64 encoding  

## Installation

Build Caddy with this plugin using [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
xcaddy build --with github.com/hookenz/caddy-signed-urls
```

Or add it to your `go.mod`:

```bash
go get github.com/hookenz/caddy-signed-urls
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
    algorithm "sha256"             # Optional, default: sha256
}
```

### Configuration Options

| Option      | Type   | Default  | Description                     |
|-------------|--------|---------|---------------------------------|
| `secret`    | string | (required) | Secret key for HMAC signing      |
| `algorithm` | string | `sha256` | The HMAC algorithm to use       |

## Generating Signed URLs

### Go Example

```go
package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "crypto/sha512"
    "encoding/base64"
    "fmt"
    "hash"
)

func generateSignedURL(secret, path, algorithm string) string {
    var h hash.Hash
    switch algorithm {
    case "sha256":
        h = hmac.New(sha256.New, []byte(secret))
    case "sha384":
        h = hmac.New(sha512.New384, []byte(secret))
    case "sha512":
        h = hmac.New(sha512.New, []byte(secret))
    default:
        panic("unsupported algorithm")
    }

    h.Write([]byte(path))
    signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
    return fmt.Sprintf("%s?signature=%s", path, signature)
}

func main() {
    secret := "your-secret-key"
    path := "/downloads/file.pdf"
    url := generateSignedURL(secret, path, "sha256")
    fmt.Println(url)
}
```

### Python Example

```python
import hmac
import hashlib
import base64

def generate_signed_url(secret, path, algorithm="sha256"):
    hash_map = {
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512
    }

    if algorithm not in hash_map:
        raise ValueError("Unsupported algorithm")

    sig = hmac.new(secret.encode(), path.encode(), hash_map[algorithm]).digest()
    signature = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{path}?signature={signature}"

url = generate_signed_url("your-secret-key", "/downloads/file.pdf")
print(url)
```

### Node.js Example

```javascript
const crypto = require('crypto');

function base64UrlEncode(buffer) {
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateSignedURL(secret, path, algorithm = 'sha256') {
    const algoMap = { sha256: 'sha256', sha384: 'sha384', sha512: 'sha512' };
    if (!algoMap[algorithm]) throw new Error("Unsupported algorithm");

    const sig = crypto.createHmac(algoMap[algorithm], secret).update(path).digest();
    const signature = base64UrlEncode(sig);

    return `${path}?signature=${signature}`;
}

console.log(generateSignedURL("your-secret-key", "/downloads/file.pdf"));
```

### PHP Example

```php
<?php
function generateSignedURL($secret, $path, $algorithm = 'sha256') {
    $algoMap = ['sha256'=>'sha256', 'sha384'=>'sha384', 'sha512'=>'sha512'];
    if (!isset($algoMap[$algorithm])) throw new Exception("Unsupported algorithm");

    $sig = hash_hmac($algoMap[$algorithm], $path, $secret, true);
    $signature = rtrim(strtr(base64_encode($sig), '+/', '-_'), '=');

    return $path . '?signature=' . $signature;
}

echo generateSignedURL('your-secret-key', '/downloads/file.pdf');
?>
```

## Usage Examples

### Protecting File Downloads

```caddyfile
files.example.com {
    route /secure/* {
        signed_url {
            secret "super-secret-key"
            algorithm "sha256"
        }
        file_server {
            root /var/www/secure-files
        }
    }

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
        signed_url {
            secret "api-secret-key"
            algorithm "sha256"
        }
        reverse_proxy localhost:8080
    }

    route /api/public/* {
        reverse_proxy localhost:8080
    }
}
```

## Security Considerations

- **Use strong secrets** – Minimum 32 characters, randomly generated  
- **Keep secrets secure** – Never commit to version control  
- **Use HTTPS** – Always transmit signed URLs over HTTPS to prevent interception  

## License

This plugin is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for full text.

## Related Projects

- [Caddy](https://caddyserver.com/) – The web server this plugin extends  
- [xcaddy](https://github.com/caddyserver/xcaddy) – Build tool for Caddy with plugins  
