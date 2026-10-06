#!/usr/bin/env python3
"""
push_bans.py - send the game server's ban list to the website.

WHY THIS EXISTS
    The website's host blocks every outbound connection (DNS and TCP), so the
    site can never read this server's MySQL. We reverse the direction: this
    script reads fury_bans and POSTs it to /api/bans.php, which works because
    inbound HTTP to the site is unaffected.

SETUP
    1. sudo apt install python3-pymysql        (or: pip3 install PyMySQL)
    2. Edit SITE_URL and INGEST_KEY below.
    3. Test it:      python3 push_bans.py
    4. Automate it:  crontab -e   and add the line at the bottom.

The script is idempotent - running it twice changes nothing the second time.
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request


def load_local_secrets():
    """
    Read secrets.env sitting next to this script, if it exists.

    Used for running by hand on your own machine. The file is git-ignored,
    so nothing in it reaches GitHub - in CI the values come from Actions
    secrets instead.
    """
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets.env")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

# ---------------------------------------------------------------------
# ANTI-BOT PROXY
# ---------------------------------------------------------------------
# The site sits behind an openresty proxy that challenges anything that does
# not look like a browser. Verified by test:
#   - User-Agent "python-urllib"  -> challenged, even with the cookie
#   - User-Agent "cs16-push-bans" -> challenged
#   - browser UA, no cookie       -> challenged
#   - browser UA + cookie         -> real response
# So both a browser-looking UA and the __test cookie are required.
#
# The cookie is derived from the challenge page by AES-128-CBC decrypt.
# The values have been static across every request, so a known-good copy is
# hardcoded here. If the proxy ever rotates them, the script re-solves the
# challenge automatically (needs `pip3 install cryptography`); without that
# library it fails with a clear message instead of silently doing nothing.
# ---------------------------------------------------------------------

ANTI_BOT_COOKIE = "d2e66d85d7f92b4f278ade3406190855"

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------
# Public settings have defaults. Credentials deliberately do NOT - they are
# never written into this file, so the script is safe to commit to GitHub.
# They come from environment variables, or from a git-ignored secrets.env
# sitting next to this script when you run it by hand.
# ---------------------------------------------------------------------

load_local_secrets()

# Where the website lives. No trailing slash.
SITE_URL = os.environ.get("BANS_SITE_URL", "https://fury.site.je")

# Shown in the admin panel so you know where a push came from.
SOURCE = os.environ.get("BANS_SOURCE", "fury_bans")

# Game database - read locally.
DB_HOST = os.environ.get("BANS_DB_HOST", "127.0.0.1")
DB_PORT = int(os.environ.get("BANS_DB_PORT", "3306"))
DB_USER = os.environ.get("BANS_DB_USER", "")
DB_PASS = os.environ.get("BANS_DB_PASS", "")
DB_NAME = os.environ.get("BANS_DB_NAME", "")
DB_TABLE = os.environ.get("BANS_DB_TABLE", "fury_bans")

# Must match INGEST_KEY in the website's includes/config.php.
INGEST_KEY = os.environ.get("BANS_INGEST_KEY", "")

# How long to wait for the website to answer, in seconds.
TIMEOUT = 20

REQUIRED = {
    "BANS_DB_USER": DB_USER,
    "BANS_DB_PASS": DB_PASS,
    "BANS_DB_NAME": DB_NAME,
    "BANS_INGEST_KEY": INGEST_KEY,
}

# ---------------------------------------------------------------------

ENDPOINT = SITE_URL.rstrip("/") + "/api/bans.php"
MAX_BODY = 512 * 1024


def fail(msg, code=1):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(code)


def fetch_rows():
    """Read every ban from the game database. Returns a list of dicts."""
    try:
        import pymysql
    except ImportError:
        fail("PyMySQL is not installed. Run:  sudo apt install python3-pymysql")

    try:
        conn = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME,
            charset="utf8mb4",
            connect_timeout=10,
            read_timeout=15,
        )
    except Exception as e:
        fail("could not connect to the game database: %s" % e)

    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("SELECT * FROM `%s`" % DB_TABLE)
            return list(cur.fetchall())
    except Exception as e:
        fail("could not read %s: %s" % (DB_TABLE, e))
    finally:
        conn.close()


def build_payload(rows):
    """Match the schema the website's /api/bans.php documents."""
    bans = []
    for r in rows:
        auth = str(r.get("player_auth") or "").strip()
        if not auth:
            continue  # the website rejects rows with no primary key
        bans.append(
            {
                "player_auth": auth,
                "player_name": str(r.get("player_name") or ""),
                "admin_name": str(r.get("admin_name") or ""),
                "timeinfo": str(r.get("timeinfo") or ""),
                "reason": str(r.get("reason") or ""),
                "ip": str(r.get("ip") or ""),
                "expire": int(r.get("expire") or 0),
            }
        )
    return {"ts": int(time.time()), "source": SOURCE, "bans": bans}


def is_challenge(body):
    """Is this the anti-bot interstitial rather than our JSON answer?"""
    return "slowAES" in body and "__test=" in body


def solve_challenge(html):
    """
    Compute a fresh __test cookie from a challenge page.

    The page calls slowAES.decrypt(c, 2, a, b) - AES-128-CBC of c under key a
    with iv b - and writes the raw bytes as hex. Returns None if the values
    are missing or no crypto library is available.
    """
    m = re.findall(r'toNumbers\("([0-9a-f]+)"\)', html or "")
    if len(m) < 3:
        return None

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return None

    try:
        key, iv, ct = (bytes.fromhex(x) for x in m[:3])
        if len(key) not in (16, 24, 32) or len(iv) != 16:
            return None
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return (dec.update(ct) + dec.finalize()).hex()
    except Exception:
        return None


def http_post(url, body, cookie):
    """One attempt. Returns (status, text) or raises on network failure."""
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Api-Key": INGEST_KEY,
            "User-Agent": BROWSER_UA,
            "Cookie": "__test=" + cookie,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def push(payload):
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    if len(body) > MAX_BODY:
        fail("payload is %d bytes, over the %d byte limit" % (len(body), MAX_BODY))

    cookie = ANTI_BOT_COOKIE
    try:
        status, raw = http_post(ENDPOINT, body, cookie)
    except Exception as e:
        fail("could not reach %s: %s" % (ENDPOINT, e))

    if not is_challenge(raw):
        return status, raw

    # First attempt was intercepted. Re-solve and try exactly once more.
    fresh = solve_challenge(raw)
    if not fresh:
        fail(
            "the site returned its anti-bot challenge instead of JSON.\n"
            "  The __test cookie is stale. Install a crypto library and re-run:\n"
            "      pip3 install cryptography\n"
            "  then, if it still fails, update ANTI_BOT_COOKIE in this file\n"
            "  with the value printed by:  python3 push_bans.py --print-cookie"
        )

    try:
        status, raw = http_post(ENDPOINT, body, fresh)
    except Exception as e:
        fail("could not reach %s: %s" % (ENDPOINT, e))

    if is_challenge(raw):
        fail(
            "the site returned its anti-bot challenge twice in a row.\n"
            "  Update ANTI_BOT_COOKIE in this file (see --print-cookie)."
        )

    return status, raw


def print_cookie():
    """Fetch a challenge page and print the cookie it wants, for maintenance."""
    req = urllib.request.Request(ENDPOINT, headers={"User-Agent": BROWSER_UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            html = resp.read().decode("utf-8", "replace")
    except Exception as e:
        fail("could not reach %s: %s" % (ENDPOINT, e))

    if not is_challenge(html):
        print("No challenge present - current cookie is accepted:")
        print(ANTI_BOT_COOKIE)
        return

    fresh = solve_challenge(html)
    if not fresh:
        fail("could not solve the challenge. Install cryptography: pip3 install cryptography")
    print("Update ANTI_BOT_COOKIE in push_bans.py to:")
    print(fresh)


def main():
    ap = argparse.ArgumentParser(description="Push the game server's ban list to the website.")
    ap.add_argument("--dry-run", action="store_true", help="print the payload and exit, send nothing")
    ap.add_argument("--quiet", action="store_true", help="print nothing on success")
    ap.add_argument(
        "--print-cookie",
        action="store_true",
        help="fetch the anti-bot challenge and print the cookie value it expects",
    )
    args = ap.parse_args()

    if args.print_cookie:
        print_cookie()
        return

    missing = [k for k, v in sorted(REQUIRED.items()) if not v]
    if missing:
        fail(
            "missing credentials: %s\n"
            "  In GitHub: add them as repository secrets.\n"
            "  Locally:   put them in secrets.env next to this script:\n"
            "      BANS_DB_USER=...\n"
            "      BANS_DB_PASS=...\n"
            "      BANS_DB_NAME=...\n"
            "      BANS_INGEST_KEY=..." % ", ".join(missing)
        )

    rows = fetch_rows()
    payload = build_payload(rows)

    if args.dry_run:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    status, raw = push(payload)

    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = {}

    if status != 200 or not parsed.get("ok"):
        detail = parsed.get("detail") or parsed.get("hint") or parsed.get("error") or raw
        # Exit 0 for "not ready yet" so cron does not mail you every 5 minutes
        # while the owner still has to apply the database update.
        if status == 503:
            print("SKIPPED: %s" % detail)
            return
        fail("the website replied %d: %s" % (status, detail), 2)

    if not args.quiet:
        print(
            "OK: %d ban(s) mirrored (%d new, %d changed, %d removed)"
            % (
                parsed.get("total", 0),
                parsed.get("added", 0),
                parsed.get("updated", 0),
                parsed.get("pruned", 0),
            )
        )


if __name__ == "__main__":
    main()
