"""手机邮件 App 设置向导的数据来源（只读）。

向导要解决的是本轮真实踩过的坑：用户不知道主机名、用户名、
电子邮件这三栏到底该填什么（主机名被填成邮箱、管理员用户名被
当成默认发件人）。所以这里的值全部从服务器现成配置里抓，不让
用户凭空猜：
- 主机名：打开网页版用的那个域名（去掉端口），兜底用服务器公网 IP。
- 账号：只有管理员一个（ADMIN_USERNAME），用户名就是管理员名，
  发件人是系统设置里的默认发件人，密码一律不显示（就是管理员密码）。
- 端口与 SSL：按环境变量取 IMAP/提交口的四个端口；证书文件存在
  才推荐 993/465 + SSL 打开，否则推荐 143/587 + SSL 关闭（993/465
  没证书时服务根本不监听，属正常，不是故障）。
- 端口状态：仅对本机做 TCP 连通检测，供参考；网页与邮件服务若
  不在同一台机器上，该状态不准，以服务器上的实际监听为准。
"""

import os
import socket

from app.config import SERVER_PUBLIC_IP


def _port(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except (TypeError, ValueError):
        return default


def _cert_configured() -> bool:
    cert = os.environ.get("MAIL_IMAP_CERT") or os.environ.get("MAIL_SMTP_CERT") or ""
    key = os.environ.get("MAIL_IMAP_KEY") or os.environ.get("MAIL_SMTP_KEY") or ""
    return bool(cert and key and os.path.exists(cert) and os.path.exists(key))


def _listening(port: int) -> bool:
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=0.25)
        sock.close()
        return True
    except OSError:
        return False


def _strip_port(host: str) -> str:
    host = (host or "").strip()
    if not host:
        return ""
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.split(":")[0]


def get_imap_wizard_data(request_host: str = "") -> dict:
    host = _strip_port(request_host) or (SERVER_PUBLIC_IP or "").strip()
    imap_port = _port("MAIL_IMAP_PORT", 143)
    imaps_port = _port("MAIL_IMAPS_PORT", 993)
    submission_port = _port("MAIL_SUBMISSION_PORT", 587)
    submission_tls_port = _port("MAIL_SUBMISSION_TLS_PORT", 465)
    has_cert = _cert_configured()
    if has_cert:
        rec_in_port, rec_in_ssl = imaps_port, "打开"
        rec_out_port, rec_out_ssl = submission_tls_port, "打开"
    else:
        rec_in_port, rec_in_ssl = imap_port, "关闭"
        rec_out_port, rec_out_ssl = submission_port, "关闭"
    return {
        "host": host,
        "has_cert": has_cert,
        "imap_port": imap_port,
        "imaps_port": imaps_port,
        "submission_port": submission_port,
        "submission_tls_port": submission_tls_port,
        "rec_in_port": rec_in_port,
        "rec_in_ssl": rec_in_ssl,
        "rec_out_port": rec_out_port,
        "rec_out_ssl": rec_out_ssl,
        "ports": [
            {"port": imap_port, "name": "IMAP 收件（明文 / STARTTLS）", "listening": _listening(imap_port)},
            {"port": imaps_port, "name": "IMAP 收件（隐式 TLS）", "listening": _listening(imaps_port)},
            {"port": submission_port, "name": "SMTP 发件（STARTTLS）", "listening": _listening(submission_port)},
            {"port": submission_tls_port, "name": "SMTP 发件（隐式 TLS）", "listening": _listening(submission_tls_port)},
        ],
    }
