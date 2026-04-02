"""认证服务模块。"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from flask import flash, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash

from app.config import ADMIN_PASSWORD_HASH, ADMIN_USERNAME, SYSTEM_TITLE
from app.repositories.auth_repo import get_user_by_email
from app.ui.html_pages import LOGIN_PAGE_TEMPLATE


def sanitize_next_url(next_url: str) -> str:
    if not next_url:
        return ""
    parts = urlsplit(next_url)
    filtered_query = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key not in {"show_domain_modal", "show_user_modal", "show_smtp_modal"}
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(filtered_query), parts.fragment))


def login_view():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = get_user_by_email(email)

        next_url = sanitize_next_url(request.args.get("next") or "")

        if email == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["user_email"], session["is_admin"] = ADMIN_USERNAME, True
            return redirect(next_url or url_for("admin_view"))
        elif user and check_password_hash(user["password_hash"], password):
            session["user_email"] = user["email"]
            session.pop("is_admin", None)
            return redirect(next_url or url_for("view_emails"))
        else:
            flash("邮箱或密码错误", "error")

    return render_template_string(LOGIN_PAGE_TEMPLATE, SYSTEM_TITLE=SYSTEM_TITLE)



def logout_view():
    session.clear()
    return redirect(url_for("login"))
