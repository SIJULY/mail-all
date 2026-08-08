# -*- coding: utf-8 -*-
import asyncio
import os
import threading

from app import app
from app.services.inbound_service import run_smtp_server


if __name__ == "__main__":
    smtp_loop = asyncio.new_event_loop()

    def _smtp_loop_runner():
        asyncio.set_event_loop(smtp_loop)
        run_smtp_server(app.logger)

    smtp_thread = threading.Thread(target=_smtp_loop_runner, name="mail-smtp-loop", daemon=True)
    smtp_thread.start()

    try:
        app.run(
            host=os.environ.get("HOST", "0.0.0.0"),
            port=int(os.environ.get("PORT", "5001")),
            debug=False,
            use_reloader=False,
        )
    finally:
        smtp_loop.call_soon_threadsafe(smtp_loop.stop)
        smtp_thread.join(timeout=2)
