"""路由注册模块。"""

from app.routes.admin_routes import register_admin_routes
from app.routes.api_routes import register_api_routes
from app.routes.mail_routes import register_mail_routes
from app.routes.moemail_routes import register_moemail_routes
from app.routes.ui_routes import register_ui_routes


def register_routes(app):
    register_api_routes(app)
    register_moemail_routes(app)
    register_ui_routes(app)
    register_mail_routes(app)
    register_admin_routes(app)


__all__ = ["register_routes"]
