"""Jev end-to-end lab: one image, three roles, each exercising specific Jev hooks.

All hosts live on 192.88.96.0/24 (the 6to4 relay prefix trick the other recon
labs use: Python's SSRF guard treats it as global so probes go through, but
nothing leaves the host). Recon runs network_mode:host and reaches them over
the local bridge route. Nothing here is a real target.

ROLE=richapp   192.88.96.10 - a full PHP/Apache app: many crawlable directories,
               a JS bundle naming first-party endpoints, a /login wall, forms.
               Drives: page_type (app + login_only), ffuf_base_paths (>cap dirs),
               ffuf extensions (.php from the stack), nuclei tags (php/apache),
               hakrawler seed order (rich surface), WAF classify (bare origin).

ROLE=waf       192.88.96.20 - answers injection-looking requests with a
               Cloudflare-style challenge body but NO vendor header, so the
               static WAF check misses and the Jev WAF classifier must decide.
               Drives: waf_classify (waf_detected=true via Jev), page_type.

ROLE=thin      192.88.96.30 - a single "coming soon" placeholder page.
               Drives: page_type (placeholder/app) and the seed-order contrast
               (a thin host Jev should rank below the rich one).
"""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = os.environ.get("ROLE", "richapp")
PORT = int(os.environ.get("PORT", "80"))

# A JS bundle naming many first-party endpoints. Katana/Hakrawler crawl the
# links, jsluice reads this, and the distinct first path segments become the
# smart-fuzz base-path candidates (ffuf_base_paths) - well above a low cap.
APP_JS = b"""// app bundle v3
const API = "/api/v1";
fetch(API + "/users");
fetch(API + "/orders");
fetch("/admin/dashboard");
fetch("/backup/db.sql");
fetch("/config/settings.php");
fetch("/uploads/list");
fetch("/internal/metrics");
fetch("/reports/latest");
const links = ["/billing/invoices", "/search?q=", "/docs/api"];
export { API, links };
"""

# Many internal links so the crawl discovers distinct base directories.
_LINKS = """
<ul>
  <li><a href="/about">About</a></li>
  <li><a href="/login">Login</a></li>
  <li><a href="/admin/dashboard">Admin</a></li>
  <li><a href="/api/v1/users">API users</a></li>
  <li><a href="/backup/db.sql">Backup</a></li>
  <li><a href="/config/settings.php">Config</a></li>
  <li><a href="/uploads/list">Uploads</a></li>
  <li><a href="/images/logo.png">Images</a></li>
  <li><a href="/blog/post-1">Blog</a></li>
  <li><a href="/docs/api">Docs</a></li>
  <li><a href="/reports/latest">Reports</a></li>
  <li><a href="/billing/invoices">Billing</a></li>
  <li><a href="/user/profile.php">Profile</a></li>
  <li><a href="/search?q=test">Search</a></li>
</ul>
"""

INDEX = (f"""<!doctype html>
<html><head><title>AcmeShop - Home</title></head>
<body>
<h1>AcmeShop storefront</h1>
<p>Welcome to the AcmeShop application. Browse the catalogue, manage your
orders and account, or sign in to the admin area.</p>
{_LINKS}
<form action="/search" method="get"><input name="q"><button>Search</button></form>
<script src="/static/app.js"></script>
</body></html>
""").encode()

LOGIN = b"""<!doctype html>
<html><head><title>Sign in - AcmeShop</title></head>
<body>
<h1>Sign in to AcmeShop</h1>
<form action="/login" method="post">
  <label>Username <input name="username"></label>
  <label>Password <input type="password" name="password"></label>
  <button type="submit">Log in</button>
</form>
<p>Forgot your password? Reset it here.</p>
</body></html>
"""

ABOUT = b"""<!doctype html>
<html><head><title>About AcmeShop</title></head>
<body><h1>About</h1><p>AcmeShop is a demo storefront with an admin area,
a REST API under /api/v1 and a reporting dashboard.</p>
<script src="/static/app.js"></script></body></html>
"""

# A generic page for any discovered path, so crawled dirs resolve 200 and
# remain in scope for smart fuzz.
def _page(path: str) -> bytes:
    title = path.strip("/").split("/")[0].capitalize() or "Page"
    return (f"""<!doctype html>
<html><head><title>{title} - AcmeShop</title></head>
<body><h1>{title}</h1><p>AcmeShop {title} section.</p>
<a href="/">Home</a> <a href="/api/v1/users">API</a>
<script src="/static/app.js"></script></body></html>
""").encode()

# Cloudflare-style challenge body with NO vendor header: the static WAF check
# keys off headers and misses, so the Jev WAF classifier must recognise it.
CHALLENGE = b"""<!doctype html>
<html><head><title>Attention Required!</title></head>
<body>
<h1>Sorry, you have been blocked</h1>
<p>This website is using a security service to protect itself from online attacks.
The action you just performed triggered the security solution. There are several
actions that could trigger this block including submitting a certain word or phrase,
a SQL command or malformed data.</p>
<p>Ray ID: 7e9a1b2c3d4e5f60 - Performance &amp; security by an edge network.</p>
</body></html>
"""

THIN = b"""<!doctype html>
<html><head><title>Coming soon</title></head>
<body><h1>Coming soon</h1><p>This site is under construction.</p></body></html>
"""

_INJECTION_MARKERS = ("'", "union", "select", "../", "<script", " or 1=1", "sleep(", "etc/passwd")


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41"
    sys_version = "(Ubuntu)"

    def _send(self, status: int, body: bytes, ctype: str = "text/html",
              extra: dict | None = None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # A tech stack the ffuf extension planner and nuclei tag selector read.
        if ROLE == "richapp":
            self.send_header("X-Powered-By", "PHP/7.4.3")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _richapp(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html", "/index.php"):
            return self._send(200, INDEX)
        if path == "/static/app.js":
            return self._send(200, APP_JS, "application/javascript")
        if path == "/login":
            return self._send(200, LOGIN)
        if path == "/about":
            return self._send(200, ABOUT)
        if path.startswith("/api/"):
            return self._send(200, b'{"status":"ok","items":[]}', "application/json")
        if path == "/robots.txt":
            return self._send(200, b"User-agent: *\nDisallow: /admin\n", "text/plain")
        if path.rstrip("/") == "" or len(path) <= 1:
            return self._send(404, b"Not Found")
        # Any other discovered directory answers 200 so it stays in scope.
        return self._send(200, _page(path))

    def _waf(self):
        raw = (self.path + " " + (self.command or "")).lower()
        looks_injection = any(m in raw for m in _INJECTION_MARKERS)
        if looks_injection:
            # 403 challenge, no cf-ray/Server:cloudflare header: static misses it.
            return self._send(403, CHALLENGE)
        if self.path.split("?", 1)[0] in ("/", "/index.html"):
            return self._send(200, b"<html><head><title>AcmeEdge</title></head>"
                                   b"<body><h1>AcmeEdge portal</h1></body></html>")
        return self._send(404, b"Not Found")

    def _thin(self):
        return self._send(200, THIN)

    def do_GET(self):
        try:
            if ROLE == "waf":
                return self._waf()
            if ROLE == "thin":
                return self._thin()
            return self._richapp()
        except BrokenPipeError:
            pass

    do_HEAD = do_GET
    do_POST = do_GET

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[jev-lab] role={ROLE} listening on :{PORT}", flush=True)
    srv.serve_forever()
