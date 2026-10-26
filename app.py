# -*- coding: utf-8 -*-
import asyncio
import os
import threading

from app import app
from app.services.inbound_service import run_smtp_server


def _start_background_service(name, target):
    """开发模式下起一个后台服务线程；端口被占等异常只记日志，不拖垮 Web。"""

    def _runner():
        try:
            target()
        except Exception as exc:
            app.logger.warning(f"{name} 启动失败（Web 仍可正常用）: {exc}")

    thread = threading.Thread(target=_runner, name=name, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    smtp_loop = asyncio.new_event_loop()

    def _smtp_loop_runner():
        asyncio.set_event_loop(smtp_loop)
        run_smtp_server(app.logger)

    smtp_thread = threading.Thread(target=_smtp_loop_runner, name="mail-smtp-loop", daemon=True)
    smtp_thread.start()

    # IMAP（143/993）与 SMTP 提交口（587/465）：与 systemd 的四个服务对应，
    # 开发模式下也一并起，方便直接用邮件客户端连本机验证。
    try:
        from app.services.imap_service import main as imap_main
        from app.services.submission_service import main as submission_main

        _start_background_service("mail-imap", imap_main)
        _start_background_service("mail-submission", submission_main)
    except Exception as exc:
        app.logger.warning(f"IMAP/提交服务导入失败（Web 仍可正常用）: {exc}")

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
