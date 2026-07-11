#!/usr/bin/env python3
"""Deploy public/ to the Hetzner managed-hosting account over SFTP (ProFTPD mod_sftp).

The host's mod_sftp accepts both publickey and password auth. We use PASSWORD auth with
the same WEB_FTP_* credentials the FTPS deploy used — it reuses a known-good login and
sidesteps all the SSH-key setup (key type, authorized_keys registration, mangled newlines)
that made earlier SFTP attempts fail. If SFTP_KEY is given instead of SFTP_PASSWORD, it
falls back to key auth (auto-detecting Ed25519 / RSA / ECDSA).

Env:
  SFTP_HOST      (required)  hostname/IP of the server
  SFTP_USER      (required)  login name
  SFTP_PASSWORD  password auth (recommended)   — or —
  SFTP_KEY       private key PEM for key auth
  SFTP_PORT      default 22
  REMOTE_DIR     default "public_html" (relative to the login home; absolute is honoured)
  LOCAL_DIR      default "public"
"""
import io
import os
import posixpath
import sys

import paramiko


def log(msg: str) -> None:
    print(msg, flush=True)


def fail(msg: str) -> None:
    print(f"::error::{msg}", flush=True)
    sys.exit(1)


HOST = (os.environ.get("SFTP_HOST") or "").strip()
USER = (os.environ.get("SFTP_USER") or "").strip()
PASSWORD = os.environ.get("SFTP_PASSWORD") or None
KEY = os.environ.get("SFTP_KEY") or None
PORT = int(os.environ.get("SFTP_PORT", "22"))
REMOTE_DIR = (os.environ.get("REMOTE_DIR") or "public_html").strip()
LOCAL_DIR = os.environ.get("LOCAL_DIR", "public")

if not HOST or not USER:
    fail("SFTP_HOST and SFTP_USER must be set.")
if not PASSWORD and not KEY:
    fail("Set SFTP_PASSWORD (recommended) or SFTP_KEY.")
if not os.path.isdir(LOCAL_DIR):
    fail(f"Local directory '{LOCAL_DIR}' not found.")

log(f"Connecting to {HOST}:{PORT} as {USER} ...")
transport = paramiko.Transport((HOST, PORT))
try:
    if PASSWORD:
        transport.connect(username=USER, password=PASSWORD)
    else:
        pkey = None
        last_err = None
        for key_cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
            try:
                pkey = key_cls.from_private_key(io.StringIO(KEY))
                break
            except Exception as e:  # wrong type / passphrase / format
                last_err = e
        if pkey is None:
            fail(f"Could not parse SFTP_KEY as Ed25519/RSA/ECDSA: {last_err}")
        transport.connect(username=USER, pkey=pkey)
except paramiko.AuthenticationException:
    fail("Authentication failed - check SFTP_USER / SFTP_PASSWORD (or SFTP_KEY).")
except Exception as e:
    fail(f"Could not connect: {type(e).__name__}: {e}")

sftp = paramiko.SFTPClient.from_transport(transport)
home = sftp.normalize(".")
target = REMOTE_DIR if posixpath.isabs(REMOTE_DIR) else posixpath.join(home, REMOTE_DIR)
log(f"Login home: {home}   deploy target: {target}")

_ensured: set = set()


def ensure_remote_dir(abspath: str) -> None:
    """mkdir -p for an absolute remote path."""
    if abspath in _ensured:
        return
    parts = [p for p in abspath.split("/") if p]
    cur = ""
    for p in parts:
        cur += "/" + p
        if cur in _ensured:
            continue
        try:
            sftp.stat(cur)
        except IOError:
            log(f"mkdir {cur}")
            sftp.mkdir(cur)
        _ensured.add(cur)
    _ensured.add(abspath)


count = 0
for root, _dirs, files in os.walk(LOCAL_DIR):
    rel = os.path.relpath(root, LOCAL_DIR)
    rdir = target if rel == "." else posixpath.join(target, rel.replace(os.sep, "/"))
    ensure_remote_dir(rdir)
    for name in files:
        local_path = os.path.join(root, name)
        remote_path = posixpath.join(rdir, name)
        sftp.put(local_path, remote_path)
        log(f"uploaded {remote_path}")
        count += 1

sftp.close()
transport.close()

if count == 0:
    fail(f"No files found under '{LOCAL_DIR}' - nothing deployed.")
log(f"Deploy complete - {count} file(s) uploaded.")
