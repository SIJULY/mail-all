"""装饰器模块。"""

from functools import wraps

from flask import jsonify, redirect, request, session, url_for

from app.config import MOEMAIL_API_KEY, MOEMAIL_API_KEY_HEADER


def moemail_api_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get(MOEMAIL_API_KEY_HEADER, "").strip()
        if token != MOEMAIL_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_email" not in session:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function



def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function
