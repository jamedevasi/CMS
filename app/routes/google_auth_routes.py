"""Google sign-in (§14) — optional/secondary alternate login path. OpenID Connect for
identity only (openid/email/profile scopes — never Gmail/Drive/Calendar/contacts).
Local password + TOTP + recovery codes remain the required baseline and break-glass
path; this is purely additive.

Google sign-in never creates a new account. A Google identity must be explicitly
linked to an existing, already-authenticated local account first (the "link" flow,
started from /account) before it can be used to sign in (the "signin" flow, started
from /login). That's what makes the link step "explicit" per §14 — it can only happen
from inside a session that already proved the local password (and TOTP, if enabled),
never automatically just because a Google account's verified email happens to match
something.
"""
from flask import Blueprint, abort, flash, redirect, request, session, url_for

from app import config as app_config
from app import db
from app.auth import current_actor, login_required, safe_next_url, start_session
from app.google_oauth import oauth

bp = Blueprint("google_auth", __name__)


def _require_enabled():
    if not app_config.google_signin_enabled():
        abort(404)


@bp.route("/login/google")
def login_start():
    _require_enabled()
    if db.get_admin() is None:
        return redirect(url_for("auth.setup"))
    session["google_flow"] = "signin"
    next_url = request.args.get("next")
    if next_url:
        session["google_signin_next"] = next_url
    return oauth.google.authorize_redirect(url_for("google_auth.callback", _external=True))


@bp.route("/account/link-google")
@login_required
def link_start():
    _require_enabled()
    session["google_flow"] = "link"
    session["google_link_user_id"] = session["admin_id"]
    return oauth.google.authorize_redirect(url_for("google_auth.callback", _external=True))


@bp.route("/login/google/callback")
def callback():
    _require_enabled()
    flow = session.pop("google_flow", None)

    try:
        token = oauth.google.authorize_access_token()
    except Exception:
        flash("Google sign-in failed or was cancelled.", "warning")
        return redirect(url_for("auth.login"))

    claims = token.get("userinfo")
    sub = claims.get("sub") if claims else None
    email = claims.get("email") if claims else None
    email_verified = claims.get("email_verified") if claims else False

    if not sub or not email or not email_verified:
        flash("Your Google account's email must be verified to use it with Feast9.", "warning")
        return redirect(url_for("auth.login"))

    if flow == "link":
        return _finish_link(sub, email)
    return _finish_signin(sub, email)


def _finish_link(sub, email):
    user_id = session.pop("google_link_user_id", None)
    if not user_id:
        flash("Your session expired — start linking again from My Account.", "warning")
        return redirect(url_for("auth.login"))

    existing = db.get_user_by_google_sub(sub)
    if existing and existing["id"] != user_id:
        flash("This Google account is already linked to a different Feast9 user.", "warning")
        return redirect(url_for("account.index"))

    db.link_google_account(user_id, sub, email, actor=current_actor())
    flash(f"Google account ({email}) linked. You can now sign in with it.", "success")
    return redirect(url_for("account.index"))


def _finish_signin(sub, email):
    user = db.get_user_by_google_sub(sub)
    if not user:
        flash(
            "This Google account isn't linked to a Feast9 user yet. Log in with your "
            "password, then link it from My Account.", "warning",
        )
        return redirect(url_for("auth.login"))

    next_url = safe_next_url(session.pop("google_signin_next", None))
    start_session(user)
    db.write_audit_now(
        current_actor(), "google_sign_in", "user", user["id"], after_summary=f"google_email={email}",
    )
    return redirect(next_url)
