#!/usr/bin/env python3
"""Build the private /dashboard data files from the GameOracle Business API.

Writes two files into --out (default build/dashboard-data):
  games.json  the tracked games with the fields the dashboard shows
  auth.json   the salted PBKDF2 hash of the dashboard password

Neither file is committed. The dashboard-data workflow uploads them to
public_html/dashboard/data, which .htaccess closes to the web; index.php
reads them from disk.

Env:
  GAME_ORACLE_KEY      Business API key (go_biz_...)    required
  DASHBOARD_PASSWORD   dashboard password               optional; auth.json is
                                                        skipped when unset
Costs one GameOracle quota unit per run (a single attribute search).
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://game-oracle.com/api/business/v1/search/attributes"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "dashboard", "games.json")
PBKDF2_ITERATIONS = 200_000


def fail(msg: str) -> None:
    print(f"::error::{msg}", flush=True)
    sys.exit(1)


def dig(row: dict, path: str):
    cur = row
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def fetch(key: str, app_ids: list) -> list:
    body = json.dumps({
        "attributes": {"app_id": {"$in": app_ids}},
        "pageSize": 100,
    }).encode()
    req = urllib.request.Request(API, data=body, method="POST", headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "carbonandcapital-dashboard/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as e:
        fail(f"GameOracle returned HTTP {e.code}: {e.read()[:300]!r}")
    except urllib.error.URLError as e:
        fail(f"Could not reach GameOracle: {e.reason}")
    if not payload.get("success"):
        fail(f"GameOracle error: {payload.get('error')} ({payload.get('code')})")
    return payload.get("data") or []


def shape(row: dict) -> dict:
    return {
        "app_id": row.get("app_id"),
        "title": row.get("title"),
        "coming_soon": bool(row.get("coming_soon")),
        "early_access": bool(row.get("early_access")),
        "release_date": dig(row, "store_release_date.date"),
        "release_year": dig(row, "store_release_date.year"),
        "release_quarter": dig(row, "store_release_date.quarter"),
        "price": row.get("latest_price"),
        "is_free": bool(row.get("is_free")),
        "reviews": dig(row, "review_count.count"),
        "positive": dig(row, "review_count.perc_pos"),
        "units": dig(row, "estimated_units_sold.mid"),
        "units_low": dig(row, "estimated_units_sold.lower"),
        "units_high": dig(row, "estimated_units_sold.upper"),
        "revenue": dig(row, "estimated_revenue.mid"),
        "wishlists": dig(row, "estimated_wishlist.mid"),
        "followers": row.get("followers"),
        "peak_players_3mo": row.get("peak_players_3mo"),
        "developers": row.get("developers") or [],
        "publishers": row.get("publishers") or [],
        "capsule": row.get("capsule_img_url"),
        "short_desc": row.get("short_desc"),
        "data_date": row.get("acquired_date"),
    }


def password_record(password: str) -> dict:
    # The salt is derived rather than random so the hash, and the login cookies
    # signed with it, stay valid across the daily runs.
    salt = hashlib.sha256(b"carbonandcapital-dashboard:" + password.encode()).digest()[:16]
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return {
        "algo": "pbkdf2_sha256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": salt.hex(),
        "hash": digest.hex(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(ROOT, "build", "dashboard-data"))
    args = parser.parse_args()

    key = (os.environ.get("GAME_ORACLE_KEY") or "").strip()
    if not key:
        fail("GAME_ORACLE_KEY is not set.")

    with open(CONFIG, encoding="utf-8") as f:
        tracked = json.load(f)["games"]
    app_ids = [int(g["app_id"]) for g in tracked]

    rows = {r.get("app_id"): r for r in fetch(key, app_ids)}
    games = []
    for g in tracked:
        row = rows.get(int(g["app_id"]))
        if row is None:
            games.append({"app_id": g["app_id"], "title": g.get("title"), "missing": True})
        else:
            games.append(shape(row))

    os.makedirs(args.out, exist_ok=True)
    out = {
        "fetched_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "GameOracle",
        "games": games,
    }
    with open(os.path.join(args.out, "games.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    found = sum(1 for g in games if not g.get("missing"))
    print(f"Wrote {found}/{len(games)} games to {args.out}/games.json", flush=True)

    password = os.environ.get("DASHBOARD_PASSWORD") or ""
    if password:
        with open(os.path.join(args.out, "auth.json"), "w", encoding="utf-8") as f:
            json.dump(password_record(password), f)
        print("Wrote auth.json", flush=True)
    else:
        print("DASHBOARD_PASSWORD not set: auth.json skipped", flush=True)


if __name__ == "__main__":
    main()
