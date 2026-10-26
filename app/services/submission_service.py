"""SMTP 提交服务：给 iPhone 邮件 App 等客户端发信用的 587/465 口。

与 25 端口收信口的区别（别混用）：
- 收信口（inbound_service）：无认证，谁都能投，投进来就入库；
- 提交口（本文件）：必须先 AUTH 登录，MAIL FROM 必须等于登录邮箱
  （管理员例外：只能用系统设置里的 default_sender），否则就是开放
  中继，会被拿去群发垃圾邮件。
- 发出去的信走网页版同一套发信配置（SMTP 或 Resend），成功后按
  收件人逐封记入 sent_emails；发信失败返回 554，不记已发送。
- 587 是 STARTTLS 口（有证书才宣告 STARTTLS），465 是隐式 TLS 口
  （有证书才监听）；没证书时只有 587 明文，iPhone 上要把 SSL 关掉
  才能用，生产务必配证书。
"""

import asyncio
import base64
import binascii
import re
import ssl
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import parseaddr

from app.config import DEFAULT_SENDER
from app.repositories.db import get_db_conn
from app.services.imap_service import check_login

MAX_DATA_BYTES = 50 * 1024 * 1024


def decode_mime_header(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def extract_outbound_parts(raw: bytes):
    """从客户端 DATA 里拆出主题、正文、附件，供发信函数用。"""
    parsed = message_from_bytes(raw)
    subject = decode_mime_header(str(parsed.get("Subject") or "")).strip()
    text_body, html_body, attachments = "", "", []
    for part in parsed.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disp = str(part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()
        if disp.startswith("attachment") or filename:
            try:
                payload = part.get_payload(decode=True) or b""
            except Exception:
                payload = b""
            attachments.append({
                "filename": decode_mime_header(filename or "attachment"),
                "content_type": part.get_content_type() or "application/octet-stream",
                "content": payload,
            })
            continue
        ctype = (part.get_content_type() or "").lower()
        try:
            payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="replace") if payload else ""
        except Exception:
            text = ""
        if ctype == "text/html" and not html_body:
            html_body = text
        elif ctype == "text/plain" and not text_body:
            text_body = text
    return subject, text_body, html_body, attachments


class SubmissionSession:
    def __init__(self, reader, writer, tls_active: bool, tls_context):
        self.reader = reader
        self.writer = writer
        self.tls_active = tls_active
        self.tls_context = tls_context
        self.user_email = None
        self.is_admin = False
        self.mail_from = None
        self.rcpts = []
        self.data_mode = False

    async def send(self, text: str):
        self.writer.write(text.encode("utf-8", errors="replace") + b"\r\n")
        await self.writer.drain()

    async def handle(self):
        await self.send("220 SijulyMail submission ready")
        while True:
            line = await self.reader.readline()
            if not line:
                return
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            cmd, _, rest = text.partition(" ")
            cmd = cmd.upper()
            if cmd in ("EHLO", "HELO"):
                await self.ehlo()
            elif cmd == "STARTTLS":
                if self.tls_active or self.tls_context is None:
                    await self.send("454 TLS not available")
                    continue
                await self.send("220 Ready to start TLS")
                loop = asyncio.get_running_loop()
                old_transport = self.writer.transport
                new_reader = asyncio.StreamReader()
                protocol = asyncio.StreamReaderProtocol(new_reader)
                new_transport = await loop.start_tls(
                    old_transport, protocol, self.tls_context, server_side=True
                )
                self.reader = new_reader
                self.writer = asyncio.StreamWriter(new_transport, protocol, new_reader, loop)
                self.tls_active = True
                # STARTTLS 后认证状态清零，客户端会重发 EHLO 再 AUTH
                self.user_email, self.is_admin, self.mail_from, self.rcpts = None, False, None, []
            elif cmd == "AUTH":
                await self.auth(rest)
            elif cmd == "MAIL":
                await self.mail_from_cmd(rest)
            elif cmd == "RCPT":
                await self.rcpt_cmd(rest)
            elif cmd == "DATA":
                await self.data_cmd()
            elif cmd == "RSET":
                self.mail_from, self.rcpts = None, []
                await self.send("250 OK")
            elif cmd == "NOOP":
                await self.send("250 OK")
            elif cmd == "VRFY":
                await self.send("252 Send some mail, then")
            elif cmd == "HELP":
                await self.send("214 EHLO STARTTLS AUTH MAIL RCPT DATA RSET NOOP QUIT")
            elif cmd == "QUIT":
                await self.send("221 Bye")
                return
            else:
                await self.send("502 Command not implemented")

    async def ehlo(self):
        lines = ["250-SijulyMail"]
        if not self.tls_active and self.tls_context is not None:
            lines.append("250-STARTTLS")
        lines.append("250-AUTH PLAIN LOGIN")
        lines.append(f"250 SIZE {MAX_DATA_BYTES}")
        for line in lines:
            self.writer.write(line.encode() + b"\r\n")
        await self.writer.drain()

    async def read_auth_line(self):
        line = await self.reader.readline()
        if not line:
            return None
        return line.decode("utf-8", errors="replace").strip()

    async def do_login(self, username, password):
        user_email, is_admin = check_login(username, password)
        if not user_email:
            return False
        self.user_email, self.is_admin = user_email, is_admin
        return True

    async def auth(self, rest: str):
        parts = rest.strip().split(None, 1)
        method = parts[0].upper() if parts else ""
        initial = parts[1].strip() if len(parts) > 1 else None
        if method == "PLAIN":
            if initial and initial != "*":
                try:
                    decoded = base64.b64decode(initial).decode("utf-8", errors="replace")
                except (binascii.Error, ValueError):
                    await self.send("501 Invalid authentication data")
                    return
                fields = decoded.split("\x00")
                username = fields[1] if len(fields) >= 3 else (fields[0] if fields else "")
                password = fields[2] if len(fields) >= 3 else (fields[1] if len(fields) >= 2 else "")
            else:
                await self.send("334 ")
                blob = await self.read_auth_line()
                if blob is None or blob == "*":
                    await self.send("501 Authentication cancelled")
                    return
                try:
                    decoded = base64.b64decode(blob).decode("utf-8", errors="replace")
                except (binascii.Error, ValueError):
                    await self.send("501 Invalid authentication data")
                    return
                fields = decoded.split("\x00")
                username = fields[1] if len(fields) >= 3 else (fields[0] if fields else "")
                password = fields[2] if len(fields) >= 3 else (fields[1] if len(fields) >= 2 else "")
            if await self.do_login(username, password):
                await self.send("235 Authentication successful")
            else:
                await self.send("535 Authentication failed")
            return
        if method == "LOGIN":
            await self.send("334 VXNlcm5hbWU6")
            username_b64 = await self.read_auth_line()
            if username_b64 is None or username_b64 == "*":
                await self.send("501 Authentication cancelled")
                return
            await self.send("334 UGFzc3dvcmQ6")
            password_b64 = await self.read_auth_line()
            if password_b64 is None or password_b64 == "*":
                await self.send("501 Authentication cancelled")
                return
            try:
                username = base64.b64decode(username_b64).decode("utf-8", errors="replace")
                password = base64.b64decode(password_b64).decode("utf-8", errors="replace")
            except (binascii.Error, ValueError):
                await self.send("501 Invalid authentication data")
                return
            if await self.do_login(username, password):
                await self.send("235 Authentication successful")
            else:
                await self.send("535 Authentication failed")
            return
        await self.send("504 Unsupported authentication mechanism")

    async def mail_from_cmd(self, rest: str):
        if self.user_email is None:
            await self.send("530 Authentication required")
            return
        m = re.search(r"FROM:\s*<([^>]*)>", rest, re.I)
        if not m:
            await self.send("501 Invalid MAIL FROM")
            return
        sender = m.group(1).strip()
        if self.is_admin:
            # 管理员没有邮箱身份，只能用系统默认发件人
            from app.services.smtp_service import get_smtp_config

            allowed = (get_smtp_config().get("default_sender") or DEFAULT_SENDER or "").strip().lower()
            if allowed and sender.lower() != allowed:
                await self.send("553 MAIL FROM must be the default sender for admin")
                return
        else:
            if sender.lower() != self.user_email.lower():
                await self.send("553 MAIL FROM must match the authenticated user")
                return
        self.mail_from, self.rcpts = sender, []
        await self.send("250 OK")

    async def rcpt_cmd(self, rest: str):
        if self.mail_from is None:
            await self.send("503 Need MAIL FROM first")
            return
        m = re.search(r"TO:\s*<([^>]*)>", rest, re.I)
        if not m:
            await self.send("501 Invalid RCPT TO")
            return
        self.rcpts.append(m.group(1).strip())
        await self.send("250 OK")

    async def data_cmd(self):
        if not self.rcpts:
            await self.send("503 Need RCPT TO first")
            return
        await self.send("354 End data with <CR><LF>.<CR><LF>")
        chunks, total = [], 0
        while True:
            line = await self.reader.readline()
            if not line:
                return
            if line in (b".\r\n", b".\n"):
                break
            if line.startswith(b".."):
                line = line[1:]
            total += len(line)
            if total > MAX_DATA_BYTES:
                await self.send("552 Message too large")
                return
            chunks.append(line)
        raw = b"".join(chunks)
        subject, text_body, html_body, attachments = extract_outbound_parts(raw)
        # 主题以客户端 DATA 里的为准；正文优先 HTML，否则纯文本
        from app.services.smtp_service import get_smtp_config, send_email_via_smtp_config

        cfg = get_smtp_config()
        if not cfg.get("default_sender") and not self.is_admin:
            await self.send("554 Sending not configured (no default sender)")
            return
        failures = []
        conn = get_db_conn()
        try:
            for rcpt in self.rcpts:
                ok, msg = send_email_via_smtp_config(
                    rcpt, subject, text_body, html_body, cfg, attachments=attachments or None
                )
                if ok:
                    conn.execute(
                        "INSERT INTO sent_emails (owner_email, recipient, sender, subject, body, body_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                        (self.user_email, rcpt, self.mail_from, subject,
                         html_body if html_body.strip() else text_body,
                         "text/html" if html_body.strip() else "text/plain"),
                    )
                else:
                    failures.append(f"{rcpt}: {msg}")
            conn.commit()
        finally:
            conn.close()
        self.mail_from, self.rcpts = None, []
        if failures:
            await self.send("554 " + "; ".join(failures)[:400])
        else:
            await self.send("250 Message accepted")


def build_tls_context():
    import os

    cert = os.environ.get("MAIL_SUBMISSION_CERT") or os.environ.get("MAIL_SMTP_CERT") or ""
    key = os.environ.get("MAIL_SUBMISSION_KEY") or os.environ.get("MAIL_SMTP_KEY") or ""
    if cert and key:
        import os.path

        if os.path.exists(cert) and os.path.exists(key):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=cert, keyfile=key)
                return ctx
            except Exception as exc:
                print(f"[submission] 加载证书失败 {exc}，仅明文 587 可用")
    return None


async def run_submission_server():
    import logging
    import os

    logger = logging.getLogger("submission")
    tls_context = build_tls_context()
    host = os.environ.get("MAIL_SUBMISSION_HOST", "0.0.0.0")
    plain_port = int(os.environ.get("MAIL_SUBMISSION_PORT", "587"))
    tls_port = int(os.environ.get("MAIL_SUBMISSION_TLS_PORT", "465"))

    async def handler(reader, writer, tls_active=False):
        session = SubmissionSession(reader, writer, tls_active, tls_context)
        try:
            await session.handle()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            logger.exception(f"提交服务连接异常: {exc}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    servers = []
    servers.append(await asyncio.start_server(
        lambda r, w: handler(r, w, tls_active=False), host, plain_port
    ))
    logger.info(f"SMTP 提交明文监听 {host}:{plain_port}（有证书时支持 STARTTLS）")
    if tls_context is not None:
        servers.append(await asyncio.start_server(
            lambda r, w: handler(r, w, tls_active=True), host, tls_port, ssl=tls_context
        ))
        logger.info(f"SMTP 提交 TLS 监听 {host}:{tls_port}")
    else:
        logger.warning("未配置证书，465 端口不监听；iPhone 发件请用 465 需先配证书，或 587 明文")
    await asyncio.gather(*[s.serve_forever() for s in servers])


def main():
    asyncio.run(run_submission_server())


if __name__ == "__main__":
    main()
