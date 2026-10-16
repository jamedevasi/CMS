import pathlib

from flask import Blueprint, current_app, flash, redirect, render_template, request, send_file, session, url_for

from app import config as app_config
from app import db
from app.auth import (
    account_locked,
    check_password,
    check_recovery_code,
    complete_login,
    current_actor,
    hash_password,
    is_rate_limited,
    idle_timeout_minutes,
    login_required,
    mark_reauthenticated,
    note_failed_sign_in,
    note_unknown_sign_in,
    password_errors,
    safe_next_url,
    verify_totp_code,
)

_ACCOUNT_LOCKED = "This account is locked for a few minutes after too many wrong attempts. Try again later, or ask an administrator to unlock it."
from app.constants import DEFAULT_LOGIN_HEADING, DEFAULT_LOGIN_TAGLINE
from app.csrf import validate_csrf
from app.theme import render_theme_css, resolve_theme

bp = Blueprint("auth", __name__)

_IMAGE_EXT_TO_MIMETYPE = {"jpg": "image/jpeg", "png": "image/png", "gif": "image/gif", "webp": "image/webp"}


@bp.route("/theme.css")
def theme_css():
    """Public (no @login_required) — the login page is themed too, and CSP's style-src 'self'
    (no 'unsafe-inline') rules out an inline <style> block, so the customizable colors are
    served as their own same-origin stylesheet instead, linked after style.css in base.html so
    its :root override wins the cascade."""
    css = render_theme_css(resolve_theme())
    response = current_app.response_class(css, mimetype="text/css")
    response.headers["Cache-Control"] = "no-cache"
    return response


@bp.route("/login-image")
def login_image():
    """Public (no @login_required) — the login page needs this before the visitor has
    authenticated. Falls back to the bundled default if no custom image is configured
    or the configured file is missing (feast9_v2_agents.md §5.12)."""
    default = pathlib.Path(current_app.root_path) / "static" / "img" / "saint_apollonia.png"
    filename = db.get_setting("login_image_filename", "")
    if filename:
        custom = pathlib.Path(app_config.branding_dir()) / filename
        if custom.exists():
            ext = custom.suffix.lower().lstrip(".")
            mimetype = _IMAGE_EXT_TO_MIMETYPE.get(ext, "image/jpeg")
            return send_file(str(custom), mimetype=mimetype)
    return send_file(str(default), mimetype="image/png")


@bp.route("/")
def index():
    if db.get_admin() is None:
        return redirect(url_for("auth.setup"))
    if session.get("admin_id"):
        return redirect(url_for("dashboard.index"))
    return redirect(url_for("auth.login"))


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    if db.get_admin() is not None:
        return redirect(url_for("auth.login"))

    errors = []
    if request.method == "POST":
        validate_csrf(request.form.get("csrf_token"))
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        security_question = request.form.get("security_question", "").strip()
        security_answer = request.form.get("security_answer", "").strip()

        if not username:
            errors.append("Username is required.")
        errors.extend(password_errors(password, username))
        if password != confirm:
            errors.append("Passwords do not match.")
        if not security_question:
            errors.append("Security question is required.")
        if not security_answer:
            errors.append("Security answer is required.")

        if not errors:
            db.create_admin(
                username=username,
                password_hash=hash_password(password),
                security_question=security_question,
                security_answer_hash=hash_password(security_answer.lower()),
            )
            flash("Setup complete. Please log in.", "success")
            return redirect(url_for("auth.login"))

    return render_template("setup.html", errors=errors)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if db.get_admin() is None:
        return redirect(url_for("auth.setup"))

    errors = []
    if request.method == "POST":
        validate_csrf(request.form.get("csrf_token"))
        ip = request.remote_addr or "unknown"

        if is_rate_limited(ip):
            errors.append("Too many failed login attempts. Please try again in 15 minutes.")
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = db.get_user_by_username(username)
            if user and account_locked(user):
                # Refused even with the right password — that is what stops guessing. It still
                # counts against the address it came from.
                db.record_failed_login(ip)
                errors.append(_ACCOUNT_LOCKED)
            elif user and check_password(user["password_hash"], password):
                db.clear_failed_logins(ip)
                next_url = safe_next_url(request.args.get("next"))
                if user["totp_enabled"]:
                    session.clear()
                    session["totp_pending_user_id"] = user["id"]
                    session["totp_pending_next"] = next_url
                    return redirect(url_for("auth.login_totp"))
                complete_login(user, "password")
                return redirect(next_url)
            else:
                db.record_failed_login(ip)
                if user:
                    note_failed_sign_in(user, "wrong password")
                else:
                    note_unknown_sign_in()
                errors.append("Invalid username or password.")

    # No custom heading set -> fall back to the clinic's own name (Settings > Clinic
    # Details) before the generic app-name default, so a configured clinic shows its
    # own name here without needing to duplicate it into login_heading too.
    login_heading = db.get_setting("login_heading", "") or db.get_setting("clinic_name", "") or DEFAULT_LOGIN_HEADING
    return render_template(
        "login.html", errors=errors,
        login_heading=login_heading,
        login_tagline=db.get_setting("login_tagline", DEFAULT_LOGIN_TAGLINE),
        google_signin_enabled=app_config.google_signin_enabled(),
    )


@bp.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    pending_id = session.get("totp_pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))
    user = db.get_user_by_id(pending_id)
    if not user or not user["totp_enabled"]:
        session.clear()
        return redirect(url_for("auth.login"))
    if account_locked(user):
        session.clear()
        flash(_ACCOUNT_LOCKED, "warning")
        return redirect(url_for("auth.login"))

    errors = []
    if request.method == "POST":
        validate_csrf(request.form.get("csrf_token"))
        ip = request.remote_addr or "unknown"

        if is_rate_limited(ip):
            errors.append("Too many failed attempts. Please try again in 15 minutes.")
        else:
            code = request.form.get("code", "").strip()
            recovery_code = request.form.get("recovery_code", "").strip()
            verified = bool(code) and verify_totp_code(user["totp_secret"], code)
            if not verified and recovery_code:
                verified = db.consume_recovery_code(
                    user["id"], lambda h: check_recovery_code(h, recovery_code)
                )

            if verified:
                db.clear_failed_logins(ip)
                next_url = safe_next_url(session.get("totp_pending_next"))
                complete_login(user, "password + two-step code")
                return redirect(next_url)
            db.record_failed_login(ip)
            if note_failed_sign_in(user, "wrong two-step code"):
                session.clear()
                flash(_ACCOUNT_LOCKED, "warning")
                return redirect(url_for("auth.login"))
            errors.append("Invalid authentication code or recovery code.")

    return render_template("login_totp.html", errors=errors)


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Step 1 of self-service password reset (§5.1: "no email needed") — enter a
    username, land on the security question for that account (or, for an account without
    two-step sign-in, on the "ask an administrator" notice — see forgot_password_verify)."""
    errors = []
    if request.method == "POST":
        validate_csrf(request.form.get("csrf_token"))
        ip = request.remote_addr or "unknown"

        if is_rate_limited(ip):
            errors.append("Too many attempts. Please try again in 15 minutes.")
        else:
            username = request.form.get("username", "").strip()
            user = db.get_user_by_username(username)
            if user:
                session["reset_pending_user_id"] = user["id"]
                return redirect(url_for("auth.forgot_password_verify"))
            db.record_failed_login(ip)
            errors.append("No account found with that username.")

    return render_template("forgot_password.html", errors=errors)


@bp.route("/forgot-password/verify", methods=["GET", "POST"])
def forgot_password_verify():
    pending_id = session.get("reset_pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.forgot_password"))
    user = db.get_user_by_id(pending_id)
    if not user or not user["is_active"]:
        session.pop("reset_pending_user_id", None)
        return redirect(url_for("auth.forgot_password"))

    # A security answer is something other people can know or guess, so on its own it must
    # never be enough to get into an account. Self-service reset is therefore only for
    # accounts with two-step sign-in, and asks for the code as well; any other account gets
    # a new password from an administrator (Users > Set Password).
    if not user["totp_enabled"]:
        return render_template("forgot_password_verify.html", errors=[], self_service=False)

    errors = []
    if request.method == "POST":
        validate_csrf(request.form.get("csrf_token"))
        ip = request.remote_addr or "unknown"

        if is_rate_limited(ip):
            errors.append("Too many attempts. Please try again in 15 minutes.")
        else:
            answer = request.form.get("security_answer", "").strip().lower()
            code = request.form.get("code", "").strip()
            recovery_code = request.form.get("recovery_code", "").strip()
            new_password = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")

            # The new password is checked first so a typo in it never uses up a recovery code.
            if account_locked(user):
                errors.append(_ACCOUNT_LOCKED)
            elif password_errors(new_password, user["username"]):
                errors.extend(password_errors(new_password, user["username"]))
            elif new_password != confirm:
                errors.append("Passwords do not match.")
            elif not check_password(user["security_answer_hash"], answer):
                db.record_failed_login(ip)
                note_failed_sign_in(user, "wrong security answer")
                errors.append("Incorrect answer to the security question.")
            elif not _second_step_ok(user, code, recovery_code):
                db.record_failed_login(ip)
                note_failed_sign_in(user, "wrong two-step code")
                errors.append("Invalid authentication code or recovery code.")
            else:
                db.clear_failed_logins(ip)
                actor = {"user_id": user["id"], "role": user["role"], "ip": ip, "user_agent": ""}
                db.update_user_password(
                    user["id"], hash_password(new_password), actor=actor,
                    how="reset with security answer + two-step code",
                )
                session.pop("reset_pending_user_id", None)
                flash("Password reset. Please log in with your new password.", "success")
                return redirect(url_for("auth.login"))

    return render_template(
        "forgot_password_verify.html", errors=errors, self_service=True,
        security_question=user["security_question"],
    )


def _second_step_ok(user, code, recovery_code):
    """A current authenticator code, or an unused recovery code (used up by this)."""
    if code and verify_totp_code(user["totp_secret"], code):
        return True
    return bool(recovery_code) and db.consume_recovery_code(
        user["id"], lambda h: check_recovery_code(h, recovery_code)
    )


@bp.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    user = db.get_user_by_id(session["admin_id"])
    errors = []
    if request.method == "POST":
        validate_csrf(request.form.get("csrf_token"))
        ip = request.remote_addr or "unknown"
        if is_rate_limited(ip):
            errors.append("Too many failed attempts. Please try again in 15 minutes.")
        else:
            password = request.form.get("password", "")
            code = request.form.get("code", "").strip()
            if not check_password(user["password_hash"], password):
                db.record_failed_login(ip)
                errors.append("Incorrect password.")
            elif user["totp_enabled"] and not verify_totp_code(user["totp_secret"], code):
                db.record_failed_login(ip)
                errors.append("Invalid authentication code.")
            else:
                db.clear_failed_logins(ip)
                mark_reauthenticated()
                next_url = safe_next_url(session.pop("reauth_next", None))
                return redirect(next_url)

    return render_template("reauth.html", errors=errors, totp_enabled=bool(user["totp_enabled"]))


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    validate_csrf(request.form.get("csrf_token"))
    idle = request.form.get("reason") == "idle"
    db.write_audit_now(
        current_actor(), "logout", "user", session.get("admin_id"),
        after_summary="automatic, after inactivity" if idle else "",
    )
    session.clear()
    if idle:  # submitted by ui_actions.js's idle timer
        flash(f"You were logged out after {idle_timeout_minutes()} minutes without activity.", "warning")
    return redirect(url_for("auth.login"))


@bp.route("/session/ping")
@login_required
def session_ping():
    """Called by ui_actions.js while someone is active on a page without clicking through
    (typing a long note), so login_required's idle check counts that as activity."""
    return "", 204
