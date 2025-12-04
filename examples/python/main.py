import time
import hmac
import hashlib
import base64
import requests
from urllib.parse import urlparse, urlunparse, urlencode

def url_sign(url: str, secret: str, expires_in: int = 3600) -> str:
    parsed = urlparse(url)

    now = int(time.time())
    expires = now + expires_in

    # EXACT Go behavior: ignore original query params entirely.
    params = {
        "expires": str(expires),
    }

    # Sorted:
    sorted_query = urlencode(sorted(params.items()))

    # Sign EXACTLY: path + "?" + sorted_query
    to_sign = f"{parsed.path}?{sorted_query}"

    raw_sig = hmac.new(
        secret.encode(),
        to_sign.encode(),
        hashlib.sha256
    ).digest()

    # Go uses RawURLEncoding (no padding)
    signature = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()

    # Add signature
    params["signature"] = signature

    # Final URL must also have sorted params
    final_query = urlencode(sorted(params.items()))

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        final_query,
        parsed.fragment,
    ))


def main():
    secret = "secret-key"
    path = "/downloads/forbidden.html"

    print("=== Test 1: Unsigned URL (should fail) ===")
    unsigned_url = f"http://localhost:8080{path}"
    print("GET", unsigned_url)

    r = requests.get(unsigned_url)
    print("Status:", r.status_code)
    print("Body:", r.text)
    print()

    print("=== Test 2: Signed URL (should succeed) ===")

    signed_path = url_sign(path, secret, 3600)
    signed_url = f"http://localhost:8080{signed_path}"

    print("Signed URL:", signed_url)

    r2 = requests.get(signed_url)
    print("Status:", r2.status_code)
    print("Body:", r2.text)

if __name__ == "__main__":
    main()