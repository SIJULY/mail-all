"""应用初始化模块。"""

import logging
import os
import sys

from flask import Flask

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
    register_routes(app)
    return app


app = create_app()

__all__ = ["app", "create_app", "init_db", "CustomSMTPHandler"]
