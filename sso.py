"""Sign in with CRCMZ (Zitadel) for SlapPlayer.

Runs beside nginx on 127.0.0.1:8081; nginx forwards /auth/ here.

  /auth/login     -> Zitadel authorize (code + PKCE, public client)
  /auth/callback  -> Zitadel token + userinfo -> Jellyfin user -> Jellyfin token

The Zitadel user's ``jellyfin_user`` metadata tag names their Jellyfin account
(the same tag app.crcmz.me uses). With the Jellyfin admin key we approve a
Quick Connect code for that user, then redeem it for an ordinary user token,
so the browser only ever holds that user's token, never the admin key. People
with no tag yet are sent to app.crcmz.me's Slap once, which creates and tags
their account.

Stdlib only. Env:
  ZITADEL_ISSUER       https://auth.crcmz.me
  ZITADEL_CLIENT_ID    the SlapPlayer OIDC app (PKCE, no secret)
  PUBLIC_URL           https://slaplayer.crcmz.me
  JELLYFIN_URL         Jellyfin as this container reaches it (http://jellyfin:8096)
  JELLYFIN_PUBLIC_URL  Jellyfin as the browser reaches it (https://jelly.qureshi.io)
  JELLYFIN_TOKEN       Jellyfin admin API key
  SSO_SECRET           signs the short-lived login cookie
"""
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ISSUER = os.environ.get("ZITADEL_ISSUER", "https://auth.crcmz.me").rstrip("/")
CLIENT_ID = os.environ.get("ZITADEL_CLIENT_ID", "")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "https://slaplayer.crcmz.me").rstrip("/")
JF = os.environ.get("JELLYFIN_URL", "http://jellyfin:8096").rstrip("/")
JF_PUBLIC = os.environ.get("JELLYFIN_PUBLIC_URL", "https://jelly.qureshi.io").rstrip("/")
JF_TOKEN = os.environ.get("JELLYFIN_TOKEN", "")
SECRET = (os.environ.get("SSO_SECRET") or secrets.token_hex(32)).encode()

REDIRECT_URI = f"{PUBLIC_URL}/auth/callback"
SCOPES = "openid profile urn:zitadel:iam:user:metadata"
TAG = "jellyfin_user"
COOKIE = "slap_sso"
COOKIE_TTL = 600

logging.basicConfig(level=logging.INFO, format="sso %(levelname)s %(message)s")
log = logging.getLogger("sso")


# ── Small helpers ───────────────────────────────────────────────────────────
def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def sign(data: dict) -> str:
    body = b64url(json.dumps(data, separators=(",", ":")).encode())
    mac = b64url(hmac.new(SECRET, body.encode(), hashlib.sha256).digest())
    return f"{body}.{mac}"


def unsign(value: str) -> dict | None:
    body, _, mac = (value or "").partition(".")
    want = b64url(hmac.new(SECRET, body.encode(), hashlib.sha256).digest())
    if not body or not hmac.compare_digest(mac, want):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except ValueError:
        return None
    return data if time.time() - data.get("t", 0) < COOKIE_TTL else None


def http(method: str, url: str, *, headers: dict | None = None, form: dict | None = None,
         body: dict | None = None) -> tuple[int, dict | str]:
    data = None
    # Cloudflare in front of auth.crcmz.me bans the default Python-urllib agent (error 1010).
    headers = {"User-Agent": "SlapPlayer-SSO/1.0", **(headers or {})}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw, status = r.read(), r.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    text = raw.decode("utf-8", "replace")
    try:
        return status, json.loads(text) if text else {}
    except ValueError:
        return status, text


class Refused(Exception):
    """A sign-in we refuse, with the sentence to show the person."""


# ── Zitadel ─────────────────────────────────────────────────────────────────
def zitadel_person(code: str, verifier: str) -> tuple[str, str]:
    """Code -> (display name, jellyfin_user tag or '')."""
    s, tok = http("POST", f"{ISSUER}/oauth/v2/token", form={
        "grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID, "code_verifier": verifier,
    })
    if s != 200 or not isinstance(tok, dict) or not tok.get("access_token"):
        log.warning("token exchange failed: %s", s)
        raise Refused("CRCMZ didn't confirm that sign-in. Try again.")
    s, info = http("GET", f"{ISSUER}/oidc/v1/userinfo",
                   headers={"Authorization": f"Bearer {tok['access_token']}"})
    if s != 200 or not isinstance(info, dict):
        log.warning("userinfo failed: %s", s)
        raise Refused("CRCMZ didn't say who you are. Try again.")
    name = info.get("preferred_username") or info.get("name") or "you"
    raw = (info.get("urn:zitadel:iam:user:metadata") or {}).get(TAG) or ""
    try:
        tag = base64.b64decode(raw).decode().strip() if raw else ""
    except ValueError:
        tag = ""
    return name, tag


# ── Jellyfin ────────────────────────────────────────────────────────────────
def jellyfin_login(jf_name: str) -> dict:
    """Admin-approved Quick Connect for one user -> that user's own token."""
    admin = {"X-Emby-Token": JF_TOKEN}
    s, users = http("GET", f"{JF}/Users", headers=admin)
    if s != 200 or not isinstance(users, list):
        log.warning("jellyfin users failed: %s", s)
        raise Refused("The music server isn't answering. Try again in a minute.")
    user = next((u for u in users if (u.get("Name") or "").casefold() == jf_name.casefold()), None)
    if not user:
        raise Refused(f"Your CRCMZ account points at a music account ({jf_name}) that doesn't exist. Ask an admin.")
    if (user.get("Policy") or {}).get("IsDisabled"):
        raise Refused("Your music account is turned off. Ask an admin.")

    device = (f'MediaBrowser Client="SlapPlayer", Device="CRCMZ sign-in", '
              f'DeviceId="slaplayer-sso-{secrets.token_hex(6)}", Version="2.0.0"')
    s, qc = http("POST", f"{JF}/QuickConnect/Initiate", headers={"Authorization": device})
    if s != 200 or not isinstance(qc, dict):
        log.warning("quick connect initiate failed: %s", s)
        raise Refused("The music server didn't start the sign-in. Try again.")
    s, _ = http("POST", f"{JF}/QuickConnect/Authorize?" + urllib.parse.urlencode(
        {"code": qc["Code"], "userId": user["Id"]}), headers=admin)
    if s != 200:
        log.warning("quick connect authorize failed: %s", s)
        raise Refused("The music server didn't approve the sign-in. Try again.")
    s, auth = http("POST", f"{JF}/Users/AuthenticateWithQuickConnect",
                   headers={"Authorization": device}, body={"Secret": qc["Secret"]})
    if s != 200 or not isinstance(auth, dict) or not auth.get("AccessToken"):
        log.warning("quick connect redeem failed: %s", s)
        raise Refused("The music server didn't finish the sign-in. Try again.")
    return {"serverUrl": JF_PUBLIC, "token": auth["AccessToken"],
            "username": auth["User"]["Name"], "userId": auth["User"]["Id"], "sso": True}


# ── Pages ───────────────────────────────────────────────────────────────────
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>SlapPlayer</title>
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0a0f;color:#fff;
font:15px/1.5 system-ui,sans-serif}}main{{max-width:22rem;padding:2rem;text-align:center}}
a{{display:inline-block;margin-top:1rem;padding:.7rem 1.2rem;border-radius:.75rem;color:#fff;
text-decoration:none;background:linear-gradient(90deg,#8b5cf6,#3b82f6);font-weight:600}}</style>
</head><body><main>{body}</main>{script}</body></html>"""


def error_page(message: str, *, setup: bool = False) -> str:
    link = ('<a href="https://app.crcmz.me/app/slap">Open Slap on CRCMZ</a>' if setup
            else '<a href="/">Back to SlapPlayer</a>')
    return PAGE.format(body=f"<h1>Couldn't sign you in</h1><p>{html.escape(message)}</p>{link}", script="")


def done_page(session: dict) -> str:
    # Same origin as the player: hand over the session in localStorage, then
    # replace this page so the callback URL leaves the history.
    data = json.dumps(session).replace("<", "\\u003c")
    script = f"<script>localStorage.setItem('slaplayer_session',JSON.stringify({data}));location.replace('/');</script>"
    return PAGE.format(body="<p>Signing you in…</p>", script=script)


# ── HTTP ────────────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    server_version = "slaplayer-sso"

    def log_message(self, fmt, *args):  # no query strings (codes) in the log
        log.info("%s %s", self.command, self.path.split("?")[0])

    def send(self, status: int, body: str = "", *, location: str = "", cookie: str = ""):
        raw = body.encode()
        self.send_response(status)
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == "/auth/login":
            return self.login()
        if url.path == "/auth/callback":
            return self.callback(urllib.parse.parse_qs(url.query))
        if url.path == "/auth/health":
            return self.send(200, "ok")
        return self.send(404, error_page("That page doesn't exist."))

    def login(self):
        if not (CLIENT_ID and JF_TOKEN):
            return self.send(503, error_page("CRCMZ sign-in isn't set up on this player yet."))
        state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = b64url(hashlib.sha256(verifier.encode()).digest())
        cookie = (f"{COOKIE}={sign({'s': state, 'v': verifier, 't': int(time.time())})}; "
                  f"Path=/auth; Max-Age={COOKIE_TTL}; HttpOnly; Secure; SameSite=Lax")
        query = urllib.parse.urlencode({
            "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "response_type": "code",
            "scope": SCOPES, "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
        })
        self.send(302, location=f"{ISSUER}/oauth/v2/authorize?{query}", cookie=cookie)

    def callback(self, q: dict):
        clear = f"{COOKIE}=; Path=/auth; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
        jar = SimpleCookie(self.headers.get("Cookie") or "")
        saved = unsign(jar[COOKIE].value) if COOKIE in jar else None
        state, code = (q.get("state") or [""])[0], (q.get("code") or [""])[0]
        if q.get("error"):
            return self.send(400, error_page("Sign-in was cancelled."), cookie=clear)
        if not saved or not code or not hmac.compare_digest(state, saved.get("s", "")):
            return self.send(400, error_page("That sign-in expired. Start again."), cookie=clear)
        try:
            name, tag = zitadel_person(code, saved["v"])
            if not tag:
                return self.send(403, error_page(
                    f"{name}, your CRCMZ account isn't linked to a music account yet. "
                    "Open Slap on CRCMZ once to set it up, then come back and sign in.", setup=True), cookie=clear)
            session = jellyfin_login(tag)
        except Refused as e:
            return self.send(403, error_page(str(e)), cookie=clear)
        except Exception:  # noqa: BLE001 - never a stack trace to the browser
            log.exception("callback failed")
            return self.send(502, error_page("Something went wrong. Try again."), cookie=clear)
        log.info("signed in %s as jellyfin %s", name, session["username"])
        self.send(200, done_page(session), cookie=clear)


if __name__ == "__main__":
    if not CLIENT_ID or not JF_TOKEN:
        log.warning("ZITADEL_CLIENT_ID or JELLYFIN_TOKEN missing: /auth/login will say it isn't set up")
    ThreadingHTTPServer(("127.0.0.1", 8081), Handler).serve_forever()
