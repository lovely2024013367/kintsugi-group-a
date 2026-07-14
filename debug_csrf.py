#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "cves/python/CVE-2023-5002"))
from pgadmin_helpers import extract_login_csrf, validate_binary_path
import requests

s = requests.Session()
base = "http://localhost:5050"
lp = s.get(f"{base}/login")
login_csrf = extract_login_csrf(lp.text)
print("login csrf ok", bool(login_csrf))
s.post(
    f"{base}/authenticate/login",
    data={
        "csrf_token": login_csrf,
        "email": "vulhub@example.com",
        "password": "vulhub",
        "language": "en",
        "internal_button": "login",
    },
    allow_redirects=True,
)
for token_name, token in [("login_csrf", login_csrf)]:
    resp = validate_binary_path(s, base, token, "/usr/bin")
    print(token_name, "->", resp.status_code, resp.text[:120])
