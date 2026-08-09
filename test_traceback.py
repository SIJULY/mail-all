from app import app
from app.routes.ui_routes import compose_email
from flask import g, session
import logging

app.logger.setLevel(logging.DEBUG)

with app.test_request_context('/compose?reply_to_id=6'):
    session['user_email'] = 'sijuly@outlook.com'
    session['is_admin'] = True
    try:
        app.preprocess_request()
        # Mock flash to just print
        from flask import flash
        def mock_flash(msg, category):
            print(f"FLASH: {category} - {msg}")
        import app.routes.ui_routes
        app.routes.ui_routes.flash = mock_flash
        
        compose_email()
    except Exception as e:
        import traceback
        traceback.print_exc()

