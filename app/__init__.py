"""应用初始化模块。"""

import logging
import os
import sys

from flask import Flask, request

from app.repositories.db import init_db
from app.routes import register_routes
from app.services.inbound_service import CustomSMTPHandler


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get(
        "MAIL_SECRET_KEY", "8786d62cbb43ac06bbc8f5575844ee85b14149ac54cebd9d"
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)

    init_db()
    remembered_public_base_url = {"value": ""}

    @app.before_request
    def remember_public_base_url():
        if request.endpoint == "static":
            return
        host = (request.headers.get("X-Forwarded-Host") or request.host or "").strip()
        if not host:
            return
        proto = (request.headers.get("X-Forwarded-Proto") or request.scheme or "https").split(",")[0].strip()
        if proto not in ("http", "https"):
            proto = "https"
        public_base_url = f"{proto}://{host}".rstrip("/")
        if remembered_public_base_url["value"] == public_base_url:
            return
        try:
            from app.repositories.settings_repo import get_app_setting, set_app_setting

            if get_app_setting("public_base_url", "") != public_base_url:
                set_app_setting("public_base_url", public_base_url)
            remembered_public_base_url["value"] = public_base_url
        except Exception:
            app.logger.debug("记录公开访问地址失败", exc_info=True)

    register_routes(app)
    return app


app = create_app()

__all__ = ["app", "create_app", "init_db", "CustomSMTPHandler"]
