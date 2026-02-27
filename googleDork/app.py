"""
designed to attract scanners and search-engine “dork” traffic by exposing common vulnerable-looking URLs such as:
/wp-login.php, /phpMyAdmin/, phpunit eval-stdin paths, /admin/login.php, etc.

produces simple, realistic HTML pages for crawler/indexing and human believability,
API-like JSON endpoints to satisfy automated scanners, and LFI-style endpoints that 
can return fake system files, similar to Glastopf-like “virtual filesystem” behavior

all requests are logged to JSONL  
"""

import json
import os
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode

from flask import Flask, Response, jsonify, request

app = Flask(__name__)

PORT = int(os.getenv("PORT", "8090"))

# JSONL logging 
LOG_DIR = Path(os.getenv("LOG_DIR", Path(__file__).parent / "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "dork-lure.jsonl"

# “fake filesystem” for LFI-style 
FAKE_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "boot.ini": "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\n",
    ".env": "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_USER=app\nDB_PASS=********\n",
}

def _log(event: dict):
    event.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")
    event.setdefault("path", request.path)
    event.setdefault("method", request.method)
    event.setdefault("source_ip", request.remote_addr)
    event.setdefault("user_agent", request.headers.get("User-Agent", ""))
    event.setdefault("query_string", request.query_string.decode(errors="ignore"))
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass

def _html_page(title: str, heading: str, body_html: str) -> Response:
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <meta name="robots" content="index,follow" />
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}
    code, pre {{ background: #f6f8fa; padding: 2px 6px; border-radius: 4px; }}
    pre {{ padding: 12px; overflow: auto; }}
    .muted {{ color: #666; }}
    .box {{ border: 1px solid #ddd; padding: 16px; border-radius: 8px; max-width: 900px; }}
    a {{ color: #0969da; }}
    ul {{ line-height: 1.6; }}
  </style>
</head>
<body>
  <div class="box">
    <h1>{heading}</h1>
    {body_html}
    <hr />
    <p class="muted">
      Server: nginx/1.24.0 · Powered by: PHP/7.4 · Build: 2024.01 · Ref: {request.path}
    </p>
  </div>
</body>
</html>
"""
    return Response(html, status=200, mimetype="text/html; charset=utf-8")

@app.after_request
def add_headers(resp):
    resp.headers["Server"] = "nginx/1.24.0"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    return resp


@app.get("/robots.txt")
def robots():
    return Response("User-agent: *\nAllow: /\n", mimetype="text/plain; charset=utf-8")

@app.get("/sitemap.xml")
def sitemap():
    host = request.host_url.rstrip("/")
    paths = [
        "/wp-login.php",
        "/phpMyAdmin/",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "/admin/login.php",
        "/portal/login",
        "/vuln.php?page=../../../../etc/passwd",
        "/.env",
        "/api/users",
        "/api/search?q=test",
    ]
    urls = "\n".join([f"  <url><loc>{host}{p}</loc></url>" for p in paths])
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{urls}
</urlset>
"""
    return Response(xml, mimetype="application/xml; charset=utf-8")


@app.get("/")
def home():
    _log({"event": "home"})
    body = """
<p class="muted">Welcome. Administration and diagnostics links:</p>
<ul>
  <li><a href="/admin/login.php">Admin login</a></li>
  <li><a href="/portal/login">Staff portal</a></li>
  <li><a href="/phpMyAdmin/">Database console</a></li>
  <li><a href="/wp-login.php">WordPress login</a></li>
  <li><a href="/api">API</a></li>
</ul>
"""
    return _html_page("Welcome", "Site Index", body)


@app.get("/wp-login.php")
def wp_login():
    _log({"event": "wp_login"})
    body = """
<p class="muted">WordPress authentication endpoint.</p>
<form method="POST" action="/api/login">
  <label>Username <input name="username" value="admin" /></label><br /><br />
  <label>Password <input name="password" value="password" /></label><br /><br />
  <button type="submit">Log In</button>
</form>
<p class="muted">If login fails, contact the administrator.</p>
"""
    return _html_page("wp-login", "WordPress Login", body)

@app.get("/phpMyAdmin/")
@app.get("/pma/")
def phpmyadmin():
    _log({"event": "phpmyadmin"})
    body = """
<p class="muted">phpMyAdmin is installed but may require credentials.</p>
<ul>
  <li><a href="/api/users">List users (API)</a></li>
  <li><a href="/api/admin/settings">Admin settings (API)</a></li>
</ul>
"""
    return _html_page("phpMyAdmin", "phpMyAdmin", body)

@app.get("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php")
def phpunit_eval():
    _log({"event": "phpunit_eval"})
    body = """
<p><strong>Warning:</strong> Debug endpoint exposed.</p>
<p class="muted">If this endpoint is reachable, review deployment configuration.</p>
<ul>
  <li><a href="/health">/health</a></li>
  <li><a href="/api/search?q=1%27+union+select+1--">/api/search</a></li>
</ul>
"""
    return _html_page("phpunit", "PHPUnit Debug Utility", body)

@app.get("/admin/")
@app.get("/admin/login.php")
def admin_login():
    _log({"event": "admin_login"})
    return _html_page(
        "Admin Login",
        "Admin Console",
        """
<p class="muted">Restricted area. Authentication required.</p>
<p class="muted">Hint: default credentials may be enabled during staging.</p>
<ul>
  <li><a href="/api/admin/settings">Continue</a></li>
</ul>
""",
    )

@app.get("/portal/login")
def portal_login():
    _log({"event": "portal_login"})
    return _html_page(
        "Portal Login",
        "Staff Portal",
        """
<p class="muted">Sign in to continue.</p>
<ul>
  <li><a href="/wp-login.php">SSO Login</a></li>
</ul>
""",
    )

@app.get("/vuln.php")
def lfi_style():
    page = request.args.get("page", "")
    _log({"event": "lfi_probe", "page": page[:200]})

    lower = (page or "").lower()
    if "etc/passwd" in lower:
        return Response(FAKE_FILES["/etc/passwd"], status=200, mimetype="text/plain; charset=utf-8")
    if "boot.ini" in lower:
        return Response(FAKE_FILES["boot.ini"], status=200, mimetype="text/plain; charset=utf-8")
    if ".env" in lower:
        return Response(FAKE_FILES[".env"], status=200, mimetype="text/plain; charset=utf-8")

    body = f"""
<p class="muted">Parameter: <code>page</code></p>
<p>Requested: <code>{page}</code></p>

<p class="muted">Try:</p>
<ul>
  <li><a href="/vuln.php?{urlencode({'page': '../../../../etc/passwd'})}">../../../../etc/passwd</a></li>
  <li><a href="/vuln.php?{urlencode({'page': '../../../../boot.ini'})}">../../../../boot.ini</a></li>
  <li><a href="/vuln.php?{urlencode({'page': '../../.env'})}">../../.env</a></li>
</ul>
"""
    return _html_page("Include", "vuln.php", body)


@app.get("/health")
def health():
    _log({"event": "health"})
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat() + "Z", "uptime": 3600})

@app.get("/api")
def api_landing():
    _log({"event": "api_landing"})
    return jsonify(
        {
            "service": "dork-lure",
            "message": "API gateway",
            "endpoints": {
                "GET /api/users": "List users",
                "GET /api/search?q=": "Search",
                "POST /api/login": "Login",
                "GET /api/admin/settings": "Admin settings (restricted)",
            },
        }
    )

@app.get("/api/users")
def api_users():
    _log({"event": "api_users"})
    return jsonify(
        {
            "success": True,
            "total": 2,
            "data": [
                {"id": 1, "username": "admin", "email": "admin@example.com", "role": "admin"},
                {"id": 2, "username": "john_doe", "email": "john@example.com", "role": "user"},
            ],
        }
    )

@app.get("/api/search")
def api_search():
    q = request.args.get("q", "")
    _log({"event": "api_search", "q": q[:200]})

    # simple SQLi-looking behavior for scanners
    lowered = q.lower()
    if any(k in lowered for k in ["union", "select", "--", "sleep(", "benchmark(", "information_schema", "xp_"]):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "MySQL Error 1064: You have an error in your SQL syntax",
                    "code": "SQL_ERROR",
                    "details": f"Error near '{q[:60]}' at line 1",
                    "query": f"SELECT * FROM posts WHERE title LIKE '%{q[:60]}%'",
                }
            ),
            500,
        )

    return jsonify({"success": True, "query": q, "total": 0, "data": [], "message": "No results found"})

@app.post("/api/login")
def api_login():
    # accept form-encoded OR JSON
    username = request.form.get("username") or (request.json or {}).get("username", "")
    password = request.form.get("password") or (request.json or {}).get("password", "")
    _log({"event": "api_login", "username": str(username)[:80]})

    time.sleep(0.15) 
    return jsonify({"success": False, "error": "Invalid credentials", "code": "AUTH_FAILED"}), 401

@app.get("/api/admin/settings")
def api_admin_settings():
    _log({"event": "api_admin_settings"})
    return jsonify({"success": False, "error": "Forbidden: Admin access required", "code": "FORBIDDEN"}), 403

# common scan paths
@app.get("/.env")
@app.get("/config.php")
@app.get("/server-status")
def common_scans():
    _log({"event": "common_scan"})
    return jsonify({"success": False, "error": "Access denied", "code": "FORBIDDEN"}), 403

@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catch_all(path):
    _log({"event": "not_found", "requested_path": path[:200]})
    return jsonify({"success": False, "error": "Endpoint not found", "code": "NOT_FOUND", "path": path}), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)