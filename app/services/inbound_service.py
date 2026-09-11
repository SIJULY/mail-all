"""入站 SMTP 服务模块。"""

import asyncio
import logging
import os
import ssl

from aiosmtpd.controller import Controller

from app.services.message_service import process_email_data


class CustomSMTPHandler:
    async def handle_DATA(self, server, session_obj, envelope):
        try:
            process_email_data(envelope.rcpt_tos, envelope.content)
            return "250 OK"
        except Exception as e:
            logging.getLogger(__name__).error(f"处理邮件时发生严重错误: {e}")
            return "500 Error processing message"



def run_smtp_server(logger=None, hostname=None, port=None):
    logger = logger or logging.getLogger(__name__)
    hostname = hostname or os.environ.get("MAIL_SMTP_HOST", "0.0.0.0")
    port = int(port or os.environ.get("MAIL_SMTP_LISTEN_PORT", "25"))

    tls_context = None
    cert_file = os.environ.get("MAIL_SMTP_CERT")
    key_file = os.environ.get("MAIL_SMTP_KEY")
    if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
        try:
            tls_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            tls_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            logger.info("已加载 SSL 证书，SMTP 服务器将开启 STARTTLS 支持。")
        except Exception as e:
            logger.error(f"加载 SSL 证书失败: {e}，服务器将以明文模式运行。")
            tls_context = None
    else:
        logger.warning("未配置有效的 SSL 证书路径，SMTP 服务器将以明文模式运行。")

    controller = Controller(CustomSMTPHandler(), hostname=hostname, port=port, tls_context=tls_context)
    controller.start()
    logger.info(f"SMTP 服务器启动，监听端口 {port}...")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        logger.info("SMTP 服务器已关闭。")
