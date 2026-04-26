import base64, json, hmac, hashlib, time

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header  = b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
payload = b64(json.dumps({
    "sub": "test_user_enoch",
    "scope": "rcm:use",
    "exp": int(time.time()) + 86400 * 365,
    "iss": "workos_test"
}).encode())

sig = b64(hmac.new(b"test_secret", f"{header}.{payload}".encode(), hashlib.sha256).digest())
print(f"{header}.{payload}.{sig}")