import time
import hmac
import hashlib
import base64
import requests
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl

def url_sign(url: str, secret: str, expires_in: int = 3600) -> str:
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))

    params.pop("signature", None)

    # add or replace expires
    params["expires"] = str(int(time.time()) + expires_in)

    # sort query params by key
    sorted_params = sorted(params.items(), key=lambda x: x[0])
    sorted_query = urlencode(sorted_params)
    new_url = urlunparse(parsed._replace(query=sorted_query))

    print(new_url)

    # sign and return
    raw_sig = hmac.new(secret.encode(), new_url.encode(), hashlib.sha256).digest()
    sig = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()
        
    return f"{new_url}&signature={sig}"


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