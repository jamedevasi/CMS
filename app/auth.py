import functools
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pyotp
from flask import abort, flash, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app import db
from app.constants import NON_CLINICAL_ROLES, NON_FINANCIAL_ROLES, NON_PRIVACY_ROLES

PBKDF2_METHOD = "pbkdf2:sha256"
MAX_FAILED_ATTEMPTS = 8          # per IP address, within LOCKOUT_WINDOW_MINUTES
LOCKOUT_WINDOW_MINUTES = 15
ACCOUNT_MAX_FAILED = 5           # per account, in a row — then the account itself is locked
ACCOUNT_LOCK_MINUTES = 15

# Password rules, applied wherever a password is set (first-time setup, new user, change,
# reset) — never to an existing password at sign-in. Length over composition rules: a long
# password that isn't a known-common one beats a short one with a forced symbol.
MIN_PASSWORD_LENGTH = 10
_COMMON_PASSWORDS = frozenset("""
password password1 password12 password123 password1234 passw0rd passw0rd123 p@ssw0rd p@ssword123
1234567890 12345678910 0123456789 0987654321 1111111111 0000000000 1q2w3e4r5t 1qaz2wsx3edc
qwertyuiop qwerty12345 qwerty123456 asdfghjkl1 asdfghjkl123 zxcvbnm123 abcdefghij abcd123456
iloveyou123 welcome123 welcome1234 admin12345 admin123456 administrator letmein123 letmein1234
changeme123 dentist123 dentist1234 dental1234 dentalclinic clinic1234 clinic12345 doctor1234
doctor12345 feast91234 feast9admin feast9feast9 india12345 kerala1234 kerala12345 football123
sunshine123 princess123 monkey12345 dragon12345 master12345 superman123 trustno1234
""".split())

# Roles that must have two-step sign-in when Settings > Sign-in Security requires it — the
# accounts that can read and write clinical and financial records. The setting
# (`require_two_factor`) is "0" (optional), "1" (these roles) or "all" (receptionists too).
TWO_FACTOR_ROLES = ("admin", "doctor", "guest_doctor")
# Reachable without two-step sign-in while it's required but not yet set up: the setup
# itself, logging out, and the idle-timer ping (which must never be answered by a redirect).
_TWO_FACTOR_SETUP_ENDPOINTS = ("totp.setup", "totp.recovery_codes", "auth.logout", "auth.session_ping")


def password_errors(password, username=""):
    """Why `password` can't be used, as plain sentences (empty list = fine)."""
    errors = []
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    lowered = password.lower()
    too_simple = (
        lowered in _COMMON_PASSWORDS
        or len(set(lowered)) <= 3
        or (len(username) >= 3 and username.lower() in lowered)
        or re.fullmatch(r"(.{1,3})\1+", lowered) is not None
    )
    if password and too_simple:
        errors.append("That password is too easy to guess. Avoid common passwords, repeated "
                      "characters and your username.")
    return errors


def two_factor_required_for(role):
    setting = db.get_setting("require_two_factor", "0")
    return setting == "all" or (setting == "1" and role in TWO_FACTOR_ROLES)


def account_locked(user):
    """True while the account's lockout (too many failed sign-ins) is still running."""
    return bool(user.get("locked_until")) and user["locked_until"] > datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _request_actor(user_id=None, role=""):
    return {
        "user_id": user_id, "role": role, "ip": request.remote_addr or "",
        "user_agent": (request.headers.get("User-Agent") or "")[:255],
    }


def note_failed_sign_in(user, reason):
    """A wrong password, two-step code or security answer for a known account: audited, and
    counted towards locking that account. Returns True if the account is now locked."""
    return db.register_failed_sign_in(
        user["id"], ACCOUNT_MAX_FAILED, ACCOUNT_LOCK_MINUTES, actor=_request_actor(), reason=reason,
    )


def note_unknown_sign_in():
    """A sign-in attempt for a username that doesn't exist. The typed text is deliberately
    not logged — people type passwords into the username box."""
    db.write_audit_now(_request_actor(), "login_failed", "user", None, after_summary="unknown username", outcome="failure")


def complete_login(user, method):
    """The end of every successful sign-in: clears the account's failed-attempt count, starts
    the session and writes the `login_success` audit row."""
    db.clear_failed_sign_ins(user["id"])
    start_session(user)
    db.write_audit_now(current_actor(), "login_success", "user", user["id"], after_summary=f"method={method}")


def logs_view(action, entity, id_arg):
    """Decorator (below @login_required): once the view has returned normally — so not for a
    404/403 — records that the signed-in user opened that record (db.record_view)."""
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            response = view(*args, **kwargs)
            if request.method == "GET":
                db.record_view(current_actor(), action, entity, kwargs.get(id_arg))
            return response

        return wrapped

    return decorator

# "Require re-authentication (not just an active session) before high-risk actions"
# (feast9_v2_agents.md §14). A fresh login already counts — reauth_at is set at
# login — so only a session that has been idle past this window must step up again.
REAUTH_WINDOW_MINUTES = 10
RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I — avoids transcription errors

# Session lifetime (THREAT_MODEL.md's "no idle/absolute session timeout" gap). The idle limit
# is an admin setting (Settings > Automatic Logout); the absolute limit is fixed — even a
# session kept busy all day must sign in again after this long.
DEFAULT_IDLE_MINUTES = 30
MIN_IDLE_MINUTES = 5
MAX_IDLE_MINUTES = 240
ABSOLUTE_SESSION_HOURS = 12


def hash_password(password):
    return generate_password_hash(password, method=PBKDF2_METHOD)


def check_password(password_hash, password):
    return check_password_hash(password_hash, password)


def is_rate_limited(ip):
    return db.count_recent_failed_logins(ip, minutes=LOCKOUT_WINDOW_MINUTES) >= MAX_FAILED_ATTEMPTS


def _utcnow():
    return datetime.now(timezone.utc)


def _parse_ts(value):
    try:
        ts = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def idle_timeout_minutes():
    raw = db.get_setting("session_idle_minutes", str(DEFAULT_IDLE_MINUTES))
    minutes = int(raw) if raw.isdigit() else DEFAULT_IDLE_MINUTES
    return min(max(minutes, MIN_IDLE_MINUTES), MAX_IDLE_MINUTES)


def start_session(user):
    """The one place a login becomes a session — password, 2FA and Google sign-in all call
    it. Starts from an empty session (no pre-login keys carried over), and records when it
    started, when it was last used and the user's session_version (see login_required)."""
    session.clear()
    now = _utcnow().isoformat()
    session["admin_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["session_version"] = user["session_version"]
    session["login_at"] = now
    session["last_seen"] = now
    mark_reauthenticated()


def refresh_session_version():
    """After a user changes their own password / 2FA / Google link, keep *this* session
    signed in — the change bumped session_version, which ends every other session."""
    user = db.get_user_by_id(session.get("admin_id"))
    if user:
        session["session_version"] = user["session_version"]


def _session_end_reason(user):
    """Why the current session must end, or None if it's still valid."""
    if not user or not user["is_active"]:
        return "Your account is no longer active. Contact the clinic's administrator."
    if session.get("session_version") != user["session_version"]:
        return "You've been signed out because the account's password or sign-in settings changed. Please log in again."
    now = _utcnow()
    login_at = _parse_ts(session.get("login_at"))
    if login_at is None:
        return "Please log in again."
    if now - login_at > timedelta(hours=ABSOLUTE_SESSION_HOURS):
        return f"For security, a login lasts at most {ABSOLUTE_SESSION_HOURS} hours. Please log in again."
    last_seen = _parse_ts(session.get("last_seen")) or login_at
    idle = idle_timeout_minutes()
    if now - last_seen > timedelta(minutes=idle):
        return f"You were logged out after {idle} minutes without activity."
    return None


def login_required(view):
    """A valid session is: an existing, active user; the user's current session_version
    (bumped by deactivation or a password / 2FA / Google-link change); not older than
    ABSOLUTE_SESSION_HOURS; used within the idle timeout. Anything else is signed out here,
    server-side, with a message saying why."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("auth.login", next=request.path))
        user = db.get_user_by_id(session.get("admin_id"))
        reason = _session_end_reason(user)
        if reason:
            session.clear()
            flash(reason, "warning")
            return redirect(url_for("auth.login", next=request.path))
        session["last_seen"] = _utcnow().isoformat()
        # Two-step sign-in is required for this role but not set up yet: nothing else is
        # reachable until it is.
        if (not user["totp_enabled"] and two_factor_required_for(user["role"])
                and request.endpoint not in _TWO_FACTOR_SETUP_ENDPOINTS):
            flash("Your clinic requires two-step sign-in for your account. Set it up to continue.", "warning")
            return redirect(url_for("totp.setup"))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles):
    """Must be applied after (below) @login_required so a session already exists."""
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def _blocks_roles(blocked, doc):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if session.get("role") in blocked:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    decorator.__doc__ = doc
    return decorator


# Each is applied after (below) @login_required — never UI-only.
financial_access_required = _blocks_roles(
    NON_FINANCIAL_ROLES, "Blocks receptionists and guest doctors from every payment/cost/report route.")
clinical_access_required = _blocks_roles(
    NON_CLINICAL_ROLES, "Blocks receptionists from medical records: cases, notes, chart, documents.")
privacy_access_required = _blocks_roles(
    NON_PRIVACY_ROLES, "Blocks guest doctors from Privacy Requests.")


def can_view_financial_data():
    return session.get("role") not in NON_FINANCIAL_ROLES


def can_view_clinical_data():
    return session.get("role") not in NON_CLINICAL_ROLES


def can_view_privacy_requests():
    return session.get("role") not in NON_PRIVACY_ROLES


def current_actor():
    """Actor dict for db.py's audit-log writers — never store more than id/role/ip/UA."""
    return {
        "user_id": session.get("admin_id"),
        "role": session.get("role", ""),
        "ip": request.remote_addr or "",
        "user_agent": (request.headers.get("User-Agent") or "")[:255],
    }


# ── TOTP 2FA ─────────────────────────────────────────────────────────────

def generate_totp_secret():
    return pyotp.random_base32()


def totp_provisioning_uri(secret, username):
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Feast9")


def verify_totp_code(secret, code):
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:
        return False


def generate_recovery_codes(count=8):
    return [
        "-".join("".join(secrets.choice(RECOVERY_CODE_ALPHABET) for _ in range(4)) for _ in range(2))
        for _ in range(count)
    ]


def hash_recovery_code(code):
    return hash_password(code.strip().upper())


def check_recovery_code(code_hash, code):
    return check_password(code_hash, code.strip().upper())


# ── Step-up re-authentication ───────────────────────────────────────────

def mark_reauthenticated():
    session["reauth_at"] = datetime.now(timezone.utc).isoformat()


def is_reauthenticated():
    # _parse_ts tolerates the pre-fix naive-UTC format written by old sessions/tests.
    ts = _parse_ts(session.get("reauth_at"))
    if ts is None:
        return False
    return _utcnow() - ts <= timedelta(minutes=REAUTH_WINDOW_MINUTES)


def safe_next_url(url):
    """`url` if it points inside Feast9, else the dashboard — every redirect to a `next`
    address (login, two-step, Google sign-in, step-up) goes through this, so a crafted
    link like /login?next=https://evil.example can't send someone off-site after they
    sign in (an open redirect). A same-host absolute URL (the Referer) is cut down to its
    path; anything with a backslash or control character is refused, since browsers read
    a backslash as a slash ('/' + backslash + 'evil.example' becomes '//evil.example')."""
    if url and "\\" not in url and not any(ord(ch) < 32 for ch in url):
        parts = urlsplit(url)
        local = not parts.scheme and not parts.netloc
        same_host = parts.scheme in ("http", "https") and parts.netloc == request.host
        if (local or same_host) and parts.path.startswith("/") and not parts.path.startswith("//"):
            return parts.path + (f"?{parts.query}" if parts.query else "")
    return url_for("dashboard.index")


def reauth_required(view):
    """Must be applied after (below) @login_required. Redirects to a password
    (+ TOTP, if enabled) re-entry challenge when the session's last authentication
    event is older than REAUTH_WINDOW_MINUTES — a long-idle session is not enough
    on its own for user management / TOTP reset, per §14."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not is_reauthenticated():
            session["reauth_next"] = request.full_path if request.method == "GET" else request.referrer
            return redirect(url_for("auth.reauth"))
        return view(*args, **kwargs)

    return wrapped
