#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "cves/python/CVE-2023-5002"))
from pgadmin_helpers import extract_login_csrf, extract_session_csrf
import requests

s = requests.Session()
r = s.get("http://localhost:5050/login", allow_redirects=False, timeout=30)
print("login", r.status_code)
csrf = extract_login_csrf(r.text)
print("login csrf", bool(csrf))
r2 = s.post(
    "http://localhost:5050/authenticate/login",
    data={
        "csrf_token": csrf,
        "email": "vulhub@example.com",
        "password": "vulhub",
        "language": "en",
        "internal_button": "login",
    },
    allow_redirects=False,
    timeout=30,
)
print("auth", r2.status_code, r2.headers.get("Location", "")[:80])
for path in ["/browser/js/utils.js", "/browser/", "/misc/ping"]:
    r3 = s.get(f"http://localhost:5050{path}", timeout=30)
    print(path, r3.status_code, extract_session_csrf(r3.text) is not None)
    if extract_session_csrf(r3.text):
        print("csrf from", path, extract_session_csrf(r3.text)[:40])
        break
    if r3.status_code == 500:
        print("body", r3.text[:120])
