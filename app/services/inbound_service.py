"""入站 SMTP 服务模块。"""

import asyncio
import logging
import os

from aiosmtpd.controller import Controller

from app.services.message_service import process_email_data


class CustomSMTPHandler:
    async def handle_DATA(self, server, session_obj, envelope):
        try:
            process_email_data(",".join(envelope.rcpt_tos), envelope.content)
            return "250 OK"
        except Exception as e:
            logging.getLogger(__name__).error(f"处理邮件时发生严重错误: {e}")
            return "500 Error processing message"



def run_smtp_server(logger=None, hostname=None, port=None):
    logger = logger or logging.getLogger(__name__)
    hostname = hostname or os.environ.get("MAIL_SMTP_HOST", "0.0.0.0")
    port = int(port or os.environ.get("MAIL_SMTP_LISTEN_PORT", "25"))
    controller = Controller(CustomSMTPHandler(), hostname=hostname, port=port)
    controller.start()
    logger.info(f"SMTP 服务器启动，监听端口 {port}...")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        logger.info("SMTP 服务器已关闭。")
