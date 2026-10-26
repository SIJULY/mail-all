"""IMAP 服务：让 iPhone 自带邮件 App 等标准客户端直接读邮局的信。

设计口径（与网页版保持一致，不另起一套数据模型）：
- 文件夹固定四个：INBOX（未删除的收信）、Trash（已删除的收信）、
  Sent（已发送）、Drafts（草稿）。UID 就是各表的 id，稳定递增；
  UIDVALIDITY 按文件夹固定（INBOX 1、Sent 2、Drafts 3、Trash 4）。
- 登录账号就是网页登录账号：管理员 + 管理用户表里的邮箱密码，
  随机生成的 MoeMail 地址没有密码，登不上 IMAP，要先在网页管理用户
  里给那个邮箱设密码。普通用户只能看到自己收件人的信，管理员看全部。
- 标记与网页互通：\\Seen 对应 is_read，\\Flagged 对应 is_starred；
  \\Deleted 只存在本连接里，EXPUNGE 时才真正落库（INBOX 里是移到
  回收站，Trash/Sent/Drafts 里是彻底删除），连接断了没 EXPUNGE 的
  标记不生效，符合 IMAP 语义。
- 限制（v1，写明不装作全功能）：literal 参数只支持放在最后一位
  （SEARCH TEXT {n}、LOGIN 密码这种都覆盖；一条命令里多个 literal
  不支持，客户端一般不用）；CREATE/DELETE/RENAME 文件夹不支持，
  文件夹是固定的四个；IDLE 支持（新信到达会推 EXISTS）。
"""

import asyncio
import base64
import binascii
import re
import ssl
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header, make_header
from email.utils import format_datetime, getaddresses, parseaddr

from app.config import ADMIN_PASSWORD_HASH, ADMIN_USERNAME
from app.repositories.auth_repo import get_user_by_email
from app.repositories.db import get_db_conn

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# 文件夹名（小写）-> (显示名, UIDVALIDITY, 别名集合)
FOLDERS = {
    "inbox": ("INBOX", 1, set()),
    "sent": ("Sent", 2, {"sent messages"}),
    "drafts": ("Drafts", 3, set()),
    "trash": ("Trash", 4, {"deleted messages", "deleted items"}),
}


def folder_key(name: str):
    if not name:
        return None
    lowered = name.strip().strip('"').lower()
    for key, (display, _validity, aliases) in FOLDERS.items():
        if lowered == display.lower() or lowered in aliases:
            return key
    return None


def parse_db_timestamp(value):
    """库里 timestamp 是 CURRENT_TIMESTAMP 的 UTC 字符串，解析失败则用现在。"""
    if not value:
        return datetime.now(timezone.utc)
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def format_internaldate(dt: datetime) -> str:
    dt = dt.astimezone(timezone.utc)
    return f"{dt.day:02d}-{MONTHS[dt.month - 1]}-{dt.year} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def decode_mime_header(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def imap_quote(text: str) -> bytes:
    """IMAP 字符串：能用引号就用引号，否则走 literal。"""
    if text is None:
        return b"NIL"
    encoded = str(text).encode("utf-8", errors="replace")
    if b"\r" in encoded or b"\n" in encoded or b'"' in encoded or b"\\" in encoded:
        return b"{" + str(len(encoded)).encode() + b"}\r\n" + encoded
    return b'"' + encoded + b'"'


def address_list(header_value: str) -> bytes:
    """把 From/To 这类信头转成 IMAP ENVELOPE 的地址表。"""
    if not header_value:
        return b"NIL"
    addrs = [(name, addr) for name, addr in getaddresses([header_value]) if addr and "@" in addr]
    if not addrs:
        return b"NIL"
    parts = []
    for name, addr in addrs:
        mailbox, _, host = addr.partition("@")
        parts.append(b"(" + imap_quote(name or "") + b" " + imap_quote(mailbox) + b" " + imap_quote(host) + b")")
    return b"(" + b" ".join(parts) + b")"


def build_envelope(msg: dict) -> bytes:
    dt = parse_db_timestamp(msg.get("timestamp"))
    date = format_datetime(dt)
    subject = msg.get("subject") or ""
    sender = msg.get("sender") or ""
    recipient = msg.get("recipient") or ""
    message_id = msg.get("message_id") or ""
    return (
        b"(" + imap_quote(date) + b" " + imap_quote(subject) + b" "
        + address_list(sender) + b" " + address_list(sender) + b" NIL "
        + address_list(recipient) + b" NIL NIL "
        + imap_quote(message_id) + b")"
    )


def build_rfc822(msg: dict) -> bytes:
    """从库字段重建一封标准 MIME 邮件，供客户端完整下载（含附件）。"""
    dt = parse_db_timestamp(msg.get("timestamp"))
    lines = [
        f"From: {msg.get('sender') or ''}",
        f"To: {msg.get('recipient') or ''}",
        f"Subject: {msg.get('subject') or ''}",
        f"Date: {format_datetime(dt)}",
    ]
    if msg.get("message_id"):
        lines.append(f"Message-ID: {msg['message_id']}")
    lines.append("MIME-Version: 1.0")
    body = msg.get("body") or ""
    body_type = (msg.get("body_type") or "text/plain").lower()
    attachments = msg.get("attachments") or []
    body_bytes = body.encode("utf-8", errors="replace")
    if attachments:
        boundary = "===============SijulyMailPart=="
        lines.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
        out = "\r\n".join(lines) + "\r\n\r\n"
        main_type = "text/html" if "html" in body_type else "text/plain"
        out += f"--{boundary}\r\nContent-Type: {main_type}; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
        out += body + "\r\n"
        for att in attachments:
            content = att.get("content") or b""
            if isinstance(content, str):
                content = content.encode("utf-8", errors="replace")
            out += (
                f"--{boundary}\r\n"
                f"Content-Type: {att.get('content_type') or 'application/octet-stream'}; name=\"{att.get('filename') or 'attachment'}\"\r\n"
                "Content-Transfer-Encoding: base64\r\n"
                f"Content-Disposition: attachment; filename=\"{att.get('filename') or 'attachment'}\"\r\n\r\n"
                + base64.encodebytes(content).decode("ascii")
                + "\r\n"
            )
        out += f"--{boundary}--\r\n"
        return out.encode("utf-8", errors="replace")
    main_type = "text/html" if "html" in body_type else "text/plain"
    lines.append(f"Content-Type: {main_type}; charset=utf-8")
    lines.append("Content-Transfer-Encoding: 8bit")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", errors="replace") + body_bytes


def header_bytes(msg: dict) -> bytes:
    full = build_rfc822(msg)
    head, _, _ = full.partition(b"\r\n\r\n")
    return head + b"\r\n"


def body_part_bytes(msg: dict) -> bytes:
    full = build_rfc822(msg)
    _, _, body = full.partition(b"\r\n\r\n")
    return body


def build_bodystructure(msg: dict) -> bytes:
    body = msg.get("body") or ""
    body_type = (msg.get("body_type") or "text/plain").lower()
    subtype = "HTML" if "html" in body_type else "PLAIN"
    size = len(body.encode("utf-8", errors="replace"))
    lines = body.count("\n") + (1 if body else 0)
    single = (
        f'"TEXT" "{subtype}" ("CHARSET" "UTF-8") NIL NIL "8BIT" {size} {lines}'.encode()
    )
    attachments = msg.get("attachments") or []
    if not attachments:
        return b"(" + single + b")"
    parts = [single]
    for att in attachments:
        content = att.get("content") or b""
        if isinstance(content, str):
            content = content.encode("utf-8", errors="replace")
        parts.append(
            b'("APPLICATION" "OCTET-STREAM" ("NAME" ' + imap_quote(att.get("filename") or "attachment")
            + b') NIL NIL "BASE64" ' + str(len(content)).encode() + b")"
        )
    return b"(" + b" ".join(parts) + b' "MIXED")'


def load_folder_messages(folder: str, user_email: str, is_admin: bool):
    """取某文件夹的全部消息（按 id 升序，即 IMAP 序号顺序）。"""
    conn = get_db_conn()
    try:
        if folder == "inbox":
            where, params = "ifnull(is_deleted, 0) = 0", []
            if not is_admin:
                where += " AND recipient = ?"
                params.append(user_email)
            rows = conn.execute(
                f"SELECT * FROM received_emails WHERE {where} ORDER BY id ASC", params
            ).fetchall()
            messages = []
            for row in rows:
                item = dict(row)
                atts = conn.execute(
                    "SELECT filename, content_type, content FROM received_email_attachments WHERE email_id = ? ORDER BY id ASC",
                    (item["id"],),
                ).fetchall()
                item["attachments"] = [dict(a) for a in atts]
                messages.append(item)
            return messages
        if folder == "trash":
            where, params = "ifnull(is_deleted, 0) = 1", []
            if not is_admin:
                where += " AND recipient = ?"
                params.append(user_email)
            rows = conn.execute(
                f"SELECT * FROM received_emails WHERE {where} ORDER BY id ASC", params
            ).fetchall()
            messages = []
            for row in rows:
                item = dict(row)
                atts = conn.execute(
                    "SELECT filename, content_type, content FROM received_email_attachments WHERE email_id = ? ORDER BY id ASC",
                    (item["id"],),
                ).fetchall()
                item["attachments"] = [dict(a) for a in atts]
                messages.append(item)
            return messages
        if folder == "sent":
            where, params = "1 = 1", []
            if not is_admin:
                where = "owner_email = ?"
                params.append(user_email)
            rows = conn.execute(
                f"SELECT * FROM sent_emails WHERE {where} ORDER BY id ASC", params
            ).fetchall()
            return [
                {
                    "id": r["id"], "sender": r["sender"] or "", "recipient": r["recipient"] or "",
                    "subject": r["subject"] or "", "body": r["body"] or "",
                    "body_type": r["body_type"] or "text/plain", "timestamp": r["timestamp"],
                    "is_read": 1, "is_starred": 0, "is_deleted": 0, "message_id": "",
                    "attachments": [],
                }
                for r in rows
            ]
        if folder == "drafts":
            where, params = "1 = 1", []
            if not is_admin:
                where = "owner_email = ?"
                params.append(user_email)
            rows = conn.execute(
                f"SELECT * FROM draft_emails WHERE {where} ORDER BY id ASC", params
            ).fetchall()
            out = []
            for r in rows:
                is_html = (r["editor_mode"] or "") == "html" or bool(r["html_body"])
                out.append({
                    "id": r["id"], "sender": r["owner_email"] or "", "recipient": r["to_address"] or "",
                    "subject": r["subject"] or "",
                    "body": (r["html_body"] or r["body"] or "") if is_html else (r["body"] or ""),
                    "body_type": "text/html" if is_html else "text/plain",
                    "timestamp": r["updated_at"], "is_read": 1, "is_starred": 0, "is_deleted": 0,
                    "message_id": "", "attachments": [],
                })
            return out
        return []
    finally:
        conn.close()


def flags_for(msg: dict, deleted_uids: set) -> list:
    flags = []
    if msg.get("is_read"):
        flags.append("\\Seen")
    if msg.get("is_starred"):
        flags.append("\\Flagged")
    if msg["id"] in deleted_uids:
        flags.append("\\Deleted")
    return flags


def check_login(username: str, password: str):
    """返回 (user_email, is_admin) 或 (None, False)。密码用 werkzeug 哈希比对。"""
    if not username or password is None:
        return None, False
    try:
        from werkzeug.security import check_password_hash
    except ImportError:
        return None, False
    if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
        return ADMIN_USERNAME, True
    user = get_user_by_email(username)
    if user and check_password_hash(user["password_hash"], password):
        return user["email"], False
    return None, False


def tokenize(text: str):
    """极简 IMAP 参数分词：引号串、括号组、原子；括号组返回 list。"""
    tokens, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] in " \t":
            i += 1
        if i >= n:
            break
        ch = text[i]
        if ch == '"':
            i += 1
            buf = []
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    i += 1
                buf.append(text[i])
                i += 1
            i += 1
            tokens.append("".join(buf))
        elif ch == "(":
            depth, j, buf = 1, i + 1, []
            while j < n and depth:
                if text[j] == "(":
                    depth += 1
                elif text[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                buf.append(text[j])
                j += 1
            tokens.append(tokenize("".join(buf)))
            i = j + 1
        else:
            j = i
            while j < n and text[j] not in " \t()":
                j += 1
            tokens.append(text[i:j])
            i = j
    return tokens


def parse_seq_set(spec: str, total: int):
    """IMAP 序号集 -> 序号 list（1-based，已去重保序）。* 代表最后一封。"""
    result = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            a, _, b = part.partition(":")
            start = total if a.strip() == "*" else int(a)
            end = total if b.strip() == "*" else int(b)
            step = 1 if end >= start else -1
            for seq in range(start, end + step, step):
                if 1 <= seq <= total and seq not in result:
                    result.append(seq)
        else:
            seq = total if part == "*" else int(part)
            if 1 <= seq <= total and seq not in result:
                result.append(seq)
    return result


def parse_uid_set(spec: str, messages):
    """UID 集 -> 序号 list。UID 在这里就是各表 id。"""
    uids = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            a, _, b = part.partition(":")
            start = max(m["id"] for m in messages) if a.strip() == "*" else int(a)
            end = max(m["id"] for m in messages) if b.strip() == "*" else int(b)
            step = 1 if end >= start else -1
            for uid in range(start, end + step, step):
                uids.add(uid)
        else:
            uids.add(max(m["id"] for m in messages) if part == "*" else int(part))
    return [i + 1 for i, m in enumerate(messages) if m["id"] in uids]


def parse_fetch_atts(att_text: str):
    """解析 FETCH 属性表：返回 [(name, section_or_None, peek_bool)]。"""
    text = att_text.strip()
    if text.startswith("(") and text.endswith(")"):
        inner = text[1:-1]
    else:
        inner = text
    atts = []
    i, n = 0, len(inner)
    while i < n:
        while i < n and inner[i] in " \t":
            i += 1
        if i >= n:
            break
        upper = inner[i:].upper()
        if upper.startswith("BODYSTRUCTURE"):
            atts.append(("BODYSTRUCTURE", None, False))
            i += len("BODYSTRUCTURE")
        elif upper.startswith("BODY.PEEK["):
            end = inner.find("]", i)
            atts.append(("BODY", inner[i + len("BODY.PEEK["):end], True))
            i = end + 1
        elif upper.startswith("BODY["):
            end = inner.find("]", i)
            atts.append(("BODY", inner[i + len("BODY["):end], False))
            i = end + 1
        elif upper.startswith("BODY.PEEK"):
            atts.append(("BODY", "", True))
            i += len("BODY.PEEK")
        elif upper.startswith("BODY"):
            atts.append(("BODY", "", False))
            i += len("BODY")
        else:
            j = i
            while j < n and inner[j] not in " \t":
                j += 1
            atts.append((inner[i:j].upper(), None, False))
            i = j
    expanded = []
    for name, section, peek in atts:
        if name == "ALL":
            expanded += [("FLAGS", None, False), ("INTERNALDATE", None, False),
                         ("RFC822.SIZE", None, False), ("ENVELOPE", None, False)]
        elif name == "FAST":
            expanded += [("FLAGS", None, False), ("INTERNALDATE", None, False),
                         ("RFC822.SIZE", None, False)]
        elif name == "FULL":
            expanded += [("FLAGS", None, False), ("INTERNALDATE", None, False),
                         ("RFC822.SIZE", None, False), ("ENVELOPE", None, False),
                         ("BODY", "", False)]
        else:
            expanded.append((name, section, peek))
    return expanded


def fetch_header_section(msg: dict, section: str) -> bytes:
    """BODY[HEADER...] / BODY[TEXT] / BODY[MIME] / 分段号。"""
    section = (section or "").upper()
    if section in ("", "RFC822"):
        return build_rfc822(msg)
    if section == "HEADER" or section.startswith("HEADER.FIELDS"):
        full_head = header_bytes(msg)
        if section == "HEADER":
            return full_head
        fields_match = re.search(r"HEADER\.FIELDS\s*\(([^)]*)\)", section)
        not_match = "NOT" in section
        wanted = set()
        if fields_match:
            wanted = {f.strip().lower() for f in fields_match.group(1).split() if f.strip()}
        out_lines = []
        for line in full_head.decode("utf-8", errors="replace").split("\r\n"):
            if not line:
                continue
            name = line.split(":", 1)[0].strip().lower()
            # FIELDS: 只留 wanted；FIELDS.NOT: 排除 wanted
            if not_match:
                if name not in wanted:
                    out_lines.append(line)
            elif name in wanted:
                out_lines.append(line)
        return ("\r\n".join(out_lines) + "\r\n").encode("utf-8", errors="replace") if out_lines else b"\r\n"
    if section == "TEXT":
        return body_part_bytes(msg)
    if section == "MIME":
        full = build_rfc822(msg)
        head, _, _ = full.partition(b"\r\n\r\n")
        return head + b"\r\n"
    if section.isdigit():
        part_no = int(section)
        if part_no == 1:
            return body_part_bytes(msg)
        atts = msg.get("attachments") or []
        idx = part_no - 2
        if 0 <= idx < len(atts):
            content = atts[idx].get("content") or b""
            if isinstance(content, str):
                content = content.encode("utf-8", errors="replace")
            return content
        return b""
    return build_rfc822(msg)


def match_search(messages, tokens):
    """极简 SEARCH 求值：隐式 AND，支持 NOT、OR 和常用条件。"""
    def one_criterion(msg, crit, arg):
        text_all = f"{msg.get('sender') or ''} {msg.get('subject') or ''} {msg.get('body') or ''}".lower()
        if crit == "ALL":
            return True
        if crit == "SEEN":
            return bool(msg.get("is_read"))
        if crit == "UNSEEN":
            return not msg.get("is_read")
        if crit == "FLAGGED":
            return bool(msg.get("is_starred"))
        if crit == "UNFLAGGED":
            return not msg.get("is_starred")
        if crit == "DELETED":
            return False  # \Deleted 只存在连接内存里，SEARCH 不跨连接查它
        if crit == "UNDELETED":
            return True
        if crit == "ANSWERED":
            return False
        if crit == "DRAFT":
            return False
        if crit == "RECENT" or crit == "NEW":
            return not msg.get("is_read")
        if crit == "OLD":
            return bool(msg.get("is_read"))
        if crit == "FROM":
            return (arg or "").lower() in (msg.get("sender") or "").lower()
        if crit == "TO":
            return (arg or "").lower() in (msg.get("recipient") or "").lower()
        if crit == "SUBJECT":
            return (arg or "").lower() in (msg.get("subject") or "").lower()
        if crit == "TEXT":
            return (arg or "").lower() in text_all
        if crit == "BODY":
            return (arg or "").lower() in (msg.get("body") or "").lower()
        if crit == "HEADER":
            return False
        if crit == "LARGER":
            try:
                return len(build_rfc822(msg)) > int(arg)
            except (TypeError, ValueError):
                return False
        if crit == "SMALLER":
            try:
                return len(build_rfc822(msg)) < int(arg)
            except (TypeError, ValueError):
                return False
        return True

    def evaluate(msg, tokens):
        i, result = 0, True
        while i < len(tokens):
            tok = tokens[i]
            if isinstance(tok, list):
                i += 1
                continue
            upper = str(tok).upper()
            if upper == "NOT":
                crit = str(tokens[i + 1]).upper() if i + 1 < len(tokens) else "ALL"
                arg = None
                step = 2
                if crit in ("FROM", "TO", "SUBJECT", "TEXT", "BODY", "HEADER", "LARGER", "SMALLER", "UID"):
                    arg = tokens[i + 2] if i + 2 < len(tokens) else None
                    step = 3
                result = result and not one_criterion(msg, crit, arg if not isinstance(arg, list) else None)
                i += step
            elif upper == "OR":
                # OR <crit1> <crit2>：取后两个条件的或
                def take(j):
                    c = str(tokens[j]).upper()
                    a, step = None, 1
                    if c in ("FROM", "TO", "SUBJECT", "TEXT", "BODY", "HEADER", "LARGER", "SMALLER", "UID"):
                        a = tokens[j + 1] if j + 1 < len(tokens) else None
                        step = 2
                    return c, a, step
                c1, a1, s1 = take(i + 1)
                c2, a2, s2 = take(i + 1 + s1)
                result = result and (one_criterion(msg, c1, a1) or one_criterion(msg, c2, a2))
                i += 1 + s1 + s2
            elif upper == "UID":
                # UID 集在外层处理，这里按“属于本文件夹”放行
                i += 2
            else:
                arg = None
                step = 1
                if upper in ("FROM", "TO", "SUBJECT", "TEXT", "BODY", "HEADER", "LARGER", "SMALLER"):
                    arg = tokens[i + 1] if i + 1 < len(tokens) else None
                    step = 2
                result = result and one_criterion(msg, upper, arg if not isinstance(arg, list) else None)
                i += step
            if not result:
                # 仍需把剩余 token 走完以免错位？AND 短路即可直接返回 False
                return False
        return result

    matched = []
    for idx, msg in enumerate(messages, start=1):
        if evaluate(msg, tokens):
            matched.append(idx)
    return matched


class IMAPSession:
    def __init__(self, reader, writer, tls_active: bool, tls_context):
        self.reader = reader
        self.writer = writer
        self.tls_active = tls_active
        self.tls_context = tls_context
        self.user_email = None
        self.is_admin = False
        self.selected = None  # folder key
        self.deleted_uids = set()
        self.failed_logins = 0
        self.auth_pending = None  # (method, username_or_None)
        self.idle = False

    async def send(self, data: bytes):
        self.writer.write(data)
        await self.writer.drain()

    async def send_line(self, text: str):
        await self.send(text.encode("utf-8", errors="replace") + b"\r\n")

    def capability(self) -> str:
        caps = "IMAP4rev1 UIDPLUS IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN"
        if not self.tls_active and self.tls_context is not None:
            caps += " STARTTLS"
        return caps

    async def read_command(self):
        """读一条命令。literal 只支持最后一位（APPEND 的报文体除外，同样在最后）。"""
        line = await self.reader.readline()
        if not line:
            return None
        text = line.decode("utf-8", errors="replace").rstrip("\r\n")
        literals = []
        m = re.search(r"\{(\d+)(\+)?\}\s*$", text)
        if m:
            size, plus = int(m.group(1)), bool(m.group(2))
            text = text[: m.start()]
            if not plus:
                await self.send(b"+ OK\r\n")
            try:
                data = await self.reader.readexactly(size)
                tail = await self.reader.readexactly(2)
                if tail not in (b"\r\n", b"\n\r"):
                    # 客户端可能没发 CRLF 分隔（{0} 之类），不硬报错
                    pass
            except asyncio.IncompleteReadError:
                return None
            literals.append(data)
        return text, literals

    def require_auth(self, tag):
        return self.user_email is not None

    async def handle(self):
        await self.send_line(f"* OK [CAPABILITY {self.capability()}] SijulyMail IMAP ready")
        while True:
            if self.auth_pending is not None:
                # AUTHENTICATE 交互：下一行是 base64 数据（或 * 取消）
                line = await self.reader.readline()
                if not line:
                    return
                data_line = line.decode("utf-8", errors="replace").strip()
                method, username, tag = self.auth_pending
                self.auth_pending = None
                if data_line == "*":
                    await self.send_line(f"{tag} BAD Authentication cancelled")
                    continue
                try:
                    decoded = base64.b64decode(data_line).decode("utf-8", errors="replace")
                except (binascii.Error, ValueError):
                    await self.send_line(f"{tag} NO Invalid authentication data")
                    continue
                if method == "PLAIN":
                    parts = decoded.split("\x00")
                    auth_user = parts[1] if len(parts) >= 3 else (parts[0] if parts else "")
                    auth_pass = parts[2] if len(parts) >= 3 else (parts[1] if len(parts) >= 2 else "")
                    ok = await self.try_login(tag, auth_user, auth_pass)
                    if not ok:
                        await self.send_line(f"{tag} NO Login failed")
                    continue
                if method == "LOGIN":
                    if username is None:
                        await self.send(b"+ UGFzc3dvcmQ6\r\n")
                        self.auth_pending = ("LOGIN_PASS", decoded, tag)
                        continue
                    await self.send_line(f"{tag} BAD Unexpected authentication data")
                    continue
                if method == "LOGIN_PASS":
                    ok = await self.try_login(tag, username, decoded)
                    if not ok:
                        await self.send_line(f"{tag} NO Login failed")
                    continue
            got = await self.read_command()
            if got is None:
                return
            text, literals = got
            if self.idle:
                # IDLE 期间只接受 DONE（其他行按 DONE 处理后继续主循环会报错，属正常）
                if text.strip().upper() != "DONE":
                    pass
                self.idle = False
                continue
            if not text.strip():
                continue
            parts = text.split(None, 1)
            tag = parts[0]
            rest = parts[1] if len(parts) > 1 else ""
            cmd_parts = rest.split(None, 1)
            cmd = cmd_parts[0].upper() if cmd_parts else ""
            args = cmd_parts[1] if len(cmd_parts) > 1 else ""
            try:
                done = await self.dispatch(tag, cmd, args, literals)
            except Exception as exc:  # 单条命令异常不杀连接
                try:
                    await self.send_line(f"{tag} BAD {exc}")
                except Exception:
                    return
                done = True
            if done is False:
                return

    async def try_login(self, tag, username, password):
        user_email, is_admin = check_login(username, password)
        if not user_email:
            self.failed_logins += 1
            if self.failed_logins >= 5:
                await self.send_line("* BYE Too many failed logins")
                return "close"
            return False
        self.user_email, self.is_admin = user_email, is_admin
        self.failed_logins = 0
        await self.send_line(f"{tag} OK Login successful")
        return True

    def messages(self):
        return load_folder_messages(self.selected, self.user_email, self.is_admin)

    async def select_folder(self, tag, args, readonly=False):
        tokens = tokenize(args)
        if not tokens:
            await self.send_line(f"{tag} BAD Missing mailbox")
            return
        key = folder_key(str(tokens[0]))
        if key is None:
            await self.send_line(f"{tag} NO No such mailbox")
            return
        self.selected = key
        self.deleted_uids = set()
        msgs = self.messages()
        display, validity, _ = FOLDERS[key]
        unread = sum(1 for m in msgs if not m.get("is_read"))
        uidnext = (max(m["id"] for m in msgs) + 1) if msgs else 1
        await self.send_line("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
        await self.send_line(f"* {len(msgs)} EXISTS")
        await self.send_line(f"* {unread} RECENT")
        await self.send_line(f"* OK [UIDVALIDITY {validity}]")
        await self.send_line(f"* OK [UIDNEXT {uidnext}]")
        await self.send_line("* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)]")
        await self.send_line(f"{tag} OK [{'READ-ONLY' if readonly else 'READ-WRITE'}] SELECT completed")

    async def do_fetch(self, tag, args, by_uid: bool):
        if self.selected is None:
            await self.send_line(f"{tag} BAD No mailbox selected")
            return
        tokens = tokenize(args)
        if len(tokens) < 2:
            await self.send_line(f"{tag} BAD Missing FETCH arguments")
            return
        seq_spec = str(tokens[0])
        att_text = args[len(seq_spec):].strip()
        # att_text 可能是 "(FLAGS ...)" 或单个属性；tokenize 会丢括号结构，这里直接用原文解析
        atts = parse_fetch_atts(att_text)
        msgs = self.messages()
        if by_uid:
            seqs = parse_uid_set(seq_spec, msgs)
        else:
            seqs = parse_seq_set(seq_spec, len(msgs))
        # 序号 -> 消息；FETCH 带 BODY（非 PEEK）会标已读
        mark_seen_ids = []
        for seq in seqs:
            msg = msgs[seq - 1]
            items, literal_items = [], []
            rfc822 = build_rfc822(msg)
            for name, section, peek in atts:
                if name == "UID":
                    items.append(f"UID {msg['id']}".encode())
                elif name == "FLAGS":
                    flags = " ".join(flags_for(msg, self.deleted_uids))
                    items.append(f"FLAGS ({flags})".encode())
                elif name == "INTERNALDATE":
                    items.append(f'INTERNALDATE "{format_internaldate(parse_db_timestamp(msg.get("timestamp")))}"'.encode())
                elif name == "RFC822.SIZE":
                    items.append(f"RFC822.SIZE {len(rfc822)}".encode())
                elif name == "ENVELOPE":
                    items.append(b"ENVELOPE " + build_envelope(msg))
                elif name == "BODYSTRUCTURE":
                    items.append(b"BODYSTRUCTURE " + build_bodystructure(msg))
                elif name == "BODY":
                    data = fetch_header_section(msg, section)
                    label = f"BODY[{section}]" if section else "BODY[]"
                    literal_items.append((label.encode(), data))
                    if not peek:
                        mark_seen_ids.append(msg["id"])
                elif name == "RFC822":
                    literal_items.append((b"RFC822", rfc822))
                    mark_seen_ids.append(msg["id"])
                elif name == "RFC822.HEADER":
                    literal_items.append((b"RFC822.HEADER", header_bytes(msg)))
                elif name == "RFC822.TEXT":
                    literal_items.append((b"RFC822.TEXT", body_part_bytes(msg)))
                    mark_seen_ids.append(msg["id"])
            out = f"* {seq} FETCH (".encode() + b" ".join(items)
            for idx, (label, data) in enumerate(literal_items):
                if items or idx > 0:
                    out += b" "
                # literal 数据后直接跟下一个属性或右括号，不加 CRLF：
                # 客户端按字节数读完 literal 后，把剩余部分当作同一行的继续，
                # 多一个 CRLF 会让它把 ")" 误当成一条新响应。
                out += label + b" {" + str(len(data)).encode() + b"}\r\n" + data
            out += b")\r\n"
            await self.send(out)
        if mark_seen_ids and self.selected in ("inbox", "trash"):
            conn = get_db_conn()
            try:
                placeholders = ",".join("?" for _ in mark_seen_ids)
                conn.execute(
                    f"UPDATE received_emails SET is_read = 1 WHERE id IN ({placeholders})",
                    mark_seen_ids,
                )
                conn.commit()
            finally:
                conn.close()
        await self.send_line(f"{tag} OK FETCH completed")

    async def do_store(self, tag, args, by_uid: bool):
        if self.selected is None:
            await self.send_line(f"{tag} BAD No mailbox selected")
            return
        tokens = tokenize(args)
        if len(tokens) < 3:
            await self.send_line(f"{tag} BAD Missing STORE arguments")
            return
        seq_spec, action_raw = str(tokens[0]), str(tokens[1]).upper()
        flag_tokens = tokens[2] if isinstance(tokens[2], list) else [tokens[2]]
        wanted = {str(f).replace("\\", "").lower() for f in flag_tokens}
        silent = action_raw.endswith(".SILENT")
        action = action_raw.replace(".SILENT", "")
        msgs = self.messages()
        seqs = parse_uid_set(seq_spec, msgs) if by_uid else parse_seq_set(seq_spec, len(msgs))
        conn = get_db_conn()
        try:
            for seq in seqs:
                msg = msgs[seq - 1]
                uid = msg["id"]
                seen = bool(msg.get("is_read"))
                flagged = bool(msg.get("is_starred"))
                deleted = uid in self.deleted_uids
                if action == "+FLAGS":
                    if "seen" in wanted:
                        seen = True
                    if "flagged" in wanted:
                        flagged = True
                    if "deleted" in wanted:
                        deleted = True
                elif action == "-FLAGS":
                    if "seen" in wanted:
                        seen = False
                    if "flagged" in wanted:
                        flagged = False
                    if "deleted" in wanted:
                        deleted = False
                elif action == "FLAGS":
                    seen = "seen" in wanted
                    flagged = "flagged" in wanted
                    deleted = "deleted" in wanted
                else:
                    await self.send_line(f"{tag} BAD Unknown STORE action")
                    return
                if deleted:
                    self.deleted_uids.add(uid)
                else:
                    self.deleted_uids.discard(uid)
                if self.selected in ("inbox", "trash"):
                    conn.execute(
                        "UPDATE received_emails SET is_read = ?, is_starred = ? WHERE id = ?",
                        (1 if seen else 0, 1 if flagged else 0, uid),
                    )
                if not silent:
                    fake = dict(msg, is_read=seen, is_starred=flagged)
                    flags = " ".join(flags_for(fake, self.deleted_uids))
                    await self.send_line(f"* {seq} FETCH (UID {uid} FLAGS ({flags}))")
            conn.commit()
        finally:
            conn.close()
        await self.send_line(f"{tag} OK STORE completed")

    async def do_expunge(self, tag, uid_spec=None):
        if self.selected is None:
            await self.send_line(f"{tag} BAD No mailbox selected")
            return
        msgs = self.messages()
        if uid_spec is not None:
            seqs = parse_uid_set(uid_spec, msgs)
            targets = {msgs[s - 1]["id"] for s in seqs} & self.deleted_uids
        else:
            targets = set(self.deleted_uids)
        # 按序号升序逐条发 EXPUNGE，序号随已删条数递减
        removed = 0
        for seq in sorted(
            [i + 1 for i, m in enumerate(msgs) if m["id"] in targets]
        ):
            await self.send_line(f"* {seq - removed} EXPUNGE")
            removed += 1
        if targets:
            ids = list(targets)
            conn = get_db_conn()
            try:
                placeholders = ",".join("?" for _ in ids)
                if self.selected == "inbox":
                    conn.execute(
                        f"UPDATE received_emails SET is_deleted = 1, deleted_at = CURRENT_TIMESTAMP WHERE id IN ({placeholders})",
                        ids,
                    )
                elif self.selected == "trash":
                    conn.execute(
                        f"DELETE FROM received_email_attachments WHERE email_id IN ({placeholders})",
                        ids,
                    )
                    conn.execute(
                        f"DELETE FROM received_emails WHERE id IN ({placeholders})", ids
                    )
                elif self.selected == "sent":
                    conn.execute(
                        f"DELETE FROM sent_emails WHERE id IN ({placeholders})", ids
                    )
                elif self.selected == "drafts":
                    conn.execute(
                        f"DELETE FROM draft_emails WHERE id IN ({placeholders})", ids
                    )
                conn.commit()
            finally:
                conn.close()
            self.deleted_uids -= targets
        await self.send_line(f"{tag} OK EXPUNGE completed")

    async def dispatch(self, tag, cmd, args, literals):
        # 未登录可用的命令
        if cmd == "CAPABILITY":
            await self.send_line(f"* CAPABILITY {self.capability()}")
            await self.send_line(f"{tag} OK CAPABILITY completed")
            return True
        if cmd == "STARTTLS":
            if self.tls_active or self.tls_context is None:
                await self.send_line(f"{tag} BAD TLS not available")
                return True
            await self.send_line(f"{tag} OK Begin TLS negotiation now")
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
            # RFC 3501：STARTTLS 后认证状态清零
            self.user_email, self.is_admin, self.selected = None, False, None
            self.deleted_uids = set()
            return True
        if cmd == "LOGIN":
            tokens = tokenize(args)
            if literals:
                # 密码以 literal 形式在最后：tokens 是用户名，literal 是密码
                username = tokens[0] if tokens else ""
                password = literals[0].decode("utf-8", errors="replace")
            elif len(tokens) >= 2:
                username, password = str(tokens[0]), str(tokens[1])
            else:
                await self.send_line(f"{tag} BAD LOGIN requires username and password")
                return True
            result = await self.try_login(tag, username, password)
            if result == "close":
                return False
            if result is False:
                await self.send_line(f"{tag} NO Login failed")
            return True
        if cmd == "AUTHENTICATE":
            method = args.strip().split(None, 1)[0].upper() if args.strip() else ""
            if method == "PLAIN":
                rest = args.strip().split(None, 1)
                if len(rest) > 1 and rest[1].strip() != "*":
                    try:
                        decoded = base64.b64decode(rest[1].strip()).decode("utf-8", errors="replace")
                    except (binascii.Error, ValueError):
                        await self.send_line(f"{tag} NO Invalid authentication data")
                        return True
                    parts = decoded.split("\x00")
                    auth_user = parts[1] if len(parts) >= 3 else (parts[0] if parts else "")
                    auth_pass = parts[2] if len(parts) >= 3 else (parts[1] if len(parts) >= 2 else "")
                    result = await self.try_login(tag, auth_user, auth_pass)
                    if result == "close":
                        return False
                    if result is False:
                        await self.send_line(f"{tag} NO Login failed")
                    return True
                await self.send(b"+ \r\n")
                self.auth_pending = ("PLAIN", None, tag)
                return True
            if method == "LOGIN":
                await self.send(b"+ VXNlcm5hbWU6\r\n")
                self.auth_pending = ("LOGIN", None, tag)
                return True
            await self.send_line(f"{tag} NO Unsupported authentication mechanism")
            return True
        if cmd == "LOGOUT":
            await self.send_line("* BYE SijulyMail logging out")
            await self.send_line(f"{tag} OK LOGOUT completed")
            return False
        if cmd == "NOOP":
            if self.selected is not None:
                count = len(self.messages())
                await self.send_line(f"* {count} EXISTS")
            await self.send_line(f"{tag} OK NOOP completed")
            return True
        if cmd == "ID":
            await self.send_line("* ID NIL")
            await self.send_line(f"{tag} OK ID completed")
            return True
        if cmd == "NAMESPACE":
            await self.send_line('* NAMESPACE (("" "/")) NIL NIL')
            await self.send_line(f"{tag} OK NAMESPACE completed")
            return True
        if cmd == "ENABLE":
            await self.send_line(f"{tag} BAD ENABLE not supported")
            return True
        # 以下命令要求登录
        if self.user_email is None:
            await self.send_line(f"{tag} NO Please login first")
            return True
        if cmd == "LIST" or cmd == "LSUB":
            tokens = tokenize(args)
            pattern = str(tokens[1]) if len(tokens) > 1 else "*"
            if pattern == '""':
                await self.send_line('* LIST (\\Noselect) "/" ""')
            elif pattern in ("*", "%") or folder_key(pattern) is not None:
                for _key, (display, _v, _a) in FOLDERS.items():
                    await self.send_line(f'* LIST (\\HasNoChildren) "/" {display}')
            await self.send_line(f"{tag} OK {cmd} completed")
            return True
        if cmd == "SELECT" or cmd == "EXAMINE":
            await self.select_folder(tag, args, readonly=(cmd == "EXAMINE"))
            return True
        if cmd == "UNSELECT":
            self.selected, self.deleted_uids = None, set()
            await self.send_line(f"{tag} OK UNSELECT completed")
            return True
        if cmd == "CLOSE":
            if self.selected is not None:
                await self.do_expunge(tag)
                self.selected, self.deleted_uids = None, set()
            await self.send_line(f"{tag} OK CLOSE completed")
            return True
        if cmd == "CHECK":
            await self.send_line(f"{tag} OK CHECK completed")
            return True
        if cmd == "STATUS":
            tokens = tokenize(args)
            if not tokens:
                await self.send_line(f"{tag} BAD Missing mailbox")
                return True
            key = folder_key(str(tokens[0]))
            if key is None:
                await self.send_line(f"{tag} NO No such mailbox")
                return True
            msgs = load_folder_messages(key, self.user_email, self.is_admin)
            display, validity, _ = FOLDERS[key]
            unread = sum(1 for m in msgs if not m.get("is_read"))
            uidnext = (max(m["id"] for m in msgs) + 1) if msgs else 1
            await self.send_line(
                f"* STATUS {display} (MESSAGES {len(msgs)} UNSEEN {unread} RECENT {unread} UIDNEXT {uidnext} UIDVALIDITY {validity})"
            )
            await self.send_line(f"{tag} OK STATUS completed")
            return True
        if cmd == "FETCH":
            await self.do_fetch(tag, args, by_uid=False)
            return True
        if cmd == "STORE":
            await self.do_store(tag, args, by_uid=False)
            return True
        if cmd == "SEARCH":
            if self.selected is None:
                await self.send_line(f"{tag} BAD No mailbox selected")
                return True
            tokens = tokenize(args)
            if literals:
                tokens.append(literals[0].decode("utf-8", errors="replace"))
            msgs = self.messages()
            seqs = match_search(msgs, tokens)
            await self.send_line("* SEARCH" + (" " + " ".join(str(s) for s in seqs) if seqs else ""))
            await self.send_line(f"{tag} OK SEARCH completed")
            return True
        if cmd == "EXPUNGE":
            await self.do_expunge(tag)
            return True
        if cmd == "COPY" or cmd == "MOVE":
            tokens = tokenize(args)
            if len(tokens) < 2:
                await self.send_line(f"{tag} BAD Missing COPY arguments")
                return True
            if self.selected is None:
                await self.send_line(f"{tag} BAD No mailbox selected")
                return True
            target_key = folder_key(str(tokens[1]))
            if target_key is None:
                await self.send_line(f"{tag} NO No such mailbox")
                return True
            msgs = self.messages()
            seqs = parse_seq_set(str(tokens[0]), len(msgs))
            copied = await self.copy_messages(msgs, seqs, target_key)
            if copied:
                _display, validity, _ = FOLDERS[target_key]
                src_uids = ",".join(str(msgs[s - 1]["id"]) for s in seqs)
                dst_uids = ",".join(str(u) for u in copied)
                await self.send_line(f"* OK [COPYUID {validity} {src_uids} {dst_uids}]")
            if cmd == "MOVE":
                for seq in seqs:
                    self.deleted_uids.add(msgs[seq - 1]["id"])
                await self.do_expunge(tag)
                return True
            await self.send_line(f"{tag} OK COPY completed")
            return True
        if cmd == "UID":
            sub = args.strip().split(None, 1)
            sub_cmd = sub[0].upper() if sub else ""
            sub_args = sub[1] if len(sub) > 1 else ""
            if sub_cmd == "FETCH":
                await self.do_fetch(tag, sub_args, by_uid=True)
            elif sub_cmd == "STORE":
                await self.do_store(tag, sub_args, by_uid=True)
            elif sub_cmd == "SEARCH":
                if self.selected is None:
                    await self.send_line(f"{tag} BAD No mailbox selected")
                    return True
                tokens = tokenize(sub_args)
                if literals:
                    tokens.append(literals[0].decode("utf-8", errors="replace"))
                msgs = self.messages()
                seqs = match_search(msgs, tokens)
                uids = [msgs[s - 1]["id"] for s in seqs]
                await self.send_line("* SEARCH" + (" " + " ".join(str(u) for u in uids) if uids else ""))
                await self.send_line(f"{tag} OK UID SEARCH completed")
            elif sub_cmd == "COPY" or sub_cmd == "MOVE":
                tokens = tokenize(sub_args)
                if len(tokens) < 2 or self.selected is None:
                    await self.send_line(f"{tag} BAD Missing UID COPY arguments")
                    return True
                target_key = folder_key(str(tokens[1]))
                if target_key is None:
                    await self.send_line(f"{tag} NO No such mailbox")
                    return True
                msgs = self.messages()
                seqs = parse_uid_set(str(tokens[0]), msgs)
                copied = await self.copy_messages(msgs, seqs, target_key)
                if copied:
                    _display, validity, _ = FOLDERS[target_key]
                    src_uids = ",".join(str(msgs[s - 1]["id"]) for s in seqs)
                    dst_uids = ",".join(str(u) for u in copied)
                    await self.send_line(f"* OK [COPYUID {validity} {src_uids} {dst_uids}]")
                if sub_cmd == "MOVE":
                    for seq in seqs:
                        self.deleted_uids.add(msgs[seq - 1]["id"])
                    await self.do_expunge(tag)
                    return True
                await self.send_line(f"{tag} OK UID COPY completed")
            elif sub_cmd == "EXPUNGE":
                tokens = tokenize(sub_args)
                await self.do_expunge(tag, uid_spec=str(tokens[0]) if tokens else None)
            else:
                await self.send_line(f"{tag} BAD Unknown UID command")
            return True
        if cmd == "APPEND":
            tokens = tokenize(args)
            if not tokens or not literals:
                await self.send_line(f"{tag} BAD APPEND requires a literal message")
                return True
            target_key = folder_key(str(tokens[0]))
            if target_key is None:
                await self.send_line(f"{tag} NO No such mailbox")
                return True
            uid = await self.append_message(target_key, literals[0])
            _display, validity, _ = FOLDERS[target_key]
            await self.send_line(f"* OK [APPENDUID {validity} {uid}]")
            await self.send_line(f"{tag} OK APPEND completed")
            return True
        if cmd == "IDLE":
            if self.selected is None:
                await self.send_line(f"{tag} BAD No mailbox selected")
                return True
            await self.send(b"+ idling\r\n")
            self.idle = True
            before = len(self.messages())
            # 等 DONE 或新信：每 15 秒查一次库，最长 29 分钟（iPhone 常规 IDLE 超时内）
            for _ in range(116):
                try:
                    line = await asyncio.wait_for(self.reader.readline(), timeout=15)
                except asyncio.TimeoutError:
                    now = len(self.messages())
                    if now != before:
                        await self.send_line(f"* {now} EXISTS")
                        await self.send_line(f"* {now} RECENT")
                        await self.send_line(f"{tag} OK IDLE completed")
                        self.idle = False
                        return True
                    continue
                if not line:
                    return False
                if line.decode("utf-8", errors="replace").strip().upper() == "DONE":
                    now = len(self.messages())
                    if now != before:
                        await self.send_line(f"* {now} EXISTS")
                    await self.send_line(f"{tag} OK IDLE completed")
                    self.idle = False
                    return True
            await self.send_line(f"{tag} OK IDLE completed")
            self.idle = False
            return True
        if cmd in ("SUBSCRIBE", "UNSUBSCRIBE"):
            await self.send_line(f"{tag} OK {cmd} completed")
            return True
        if cmd in ("CREATE", "DELETE", "RENAME"):
            await self.send_line(f"{tag} NO Mailbox management not supported (fixed folders)")
            return True
        if cmd in ("GETQUOTA", "GETQUOTAROOT", "SETQUOTA"):
            await self.send_line(f"{tag} NO Quota not supported")
            return True
        await self.send_line(f"{tag} BAD Unknown command")
        return True

    async def copy_messages(self, msgs, seqs, target_key):
        """把消息复制到目标文件夹，返回新 id list。"""
        conn = get_db_conn()
        new_ids = []
        try:
            for seq in seqs:
                msg = msgs[seq - 1]
                if target_key in ("inbox", "trash"):
                    is_deleted = 1 if target_key == "trash" else 0
                    cur = conn.execute(
                        "INSERT INTO received_emails (recipient, sender, subject, body, body_type, message_id, is_read, is_starred, is_deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (msg.get("recipient") or self.user_email, msg.get("sender") or "",
                         msg.get("subject") or "", msg.get("body") or "",
                         msg.get("body_type") or "text/plain", msg.get("message_id") or None,
                         1 if msg.get("is_read") else 0, 1 if msg.get("is_starred") else 0, is_deleted),
                    )
                    new_id = cur.lastrowid
                    for att in msg.get("attachments") or []:
                        conn.execute(
                            "INSERT INTO received_email_attachments (email_id, filename, content_type, file_size, content) VALUES (?, ?, ?, ?, ?)",
                            (new_id, att.get("filename") or "attachment",
                             att.get("content_type") or "application/octet-stream",
                             len(att.get("content") or b""), att.get("content") or b""),
                        )
                    new_ids.append(new_id)
                elif target_key == "sent":
                    cur = conn.execute(
                        "INSERT INTO sent_emails (owner_email, recipient, sender, subject, body, body_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                        (self.user_email, msg.get("recipient") or "", msg.get("sender") or "",
                         msg.get("subject") or "", msg.get("body") or "",
                         msg.get("body_type") or "text/plain"),
                    )
                    new_ids.append(cur.lastrowid)
                elif target_key == "drafts":
                    is_html = "html" in (msg.get("body_type") or "").lower()
                    cur = conn.execute(
                        "INSERT INTO draft_emails (owner_email, to_address, subject, body, html_body, editor_mode) VALUES (?, ?, ?, ?, ?, ?)",
                        (self.user_email, msg.get("recipient") or "", msg.get("subject") or "",
                         "" if is_html else (msg.get("body") or ""),
                         msg.get("body") or "" if is_html else "",
                         "html" if is_html else "text"),
                    )
                    new_ids.append(cur.lastrowid)
            conn.commit()
        finally:
            conn.close()
        return new_ids

    async def append_message(self, target_key, raw: bytes):
        """APPEND 进来的整封 MIME：按目标文件夹入库；Sent 去重防发件重复存。"""
        parsed = message_from_bytes(raw)
        subject = decode_mime_header(str(parsed.get("Subject") or "")).strip()
        sender = decode_mime_header(str(parsed.get("From") or "")).strip() or self.user_email
        _name, sender_addr = parseaddr(sender)
        if not sender_addr:
            sender_addr = self.user_email
        to_header = decode_mime_header(str(parsed.get("To") or "")).strip()
        _tname, to_addr = parseaddr(to_header)
        message_id = str(parsed.get("Message-ID") or "").strip() or None
        text_body, html_body = "", ""
        for part in parsed.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if str(part.get("Content-Disposition") or "").lower().startswith("attachment"):
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
        body = html_body if html_body else text_body
        body_type = "text/html" if html_body else "text/plain"
        conn = get_db_conn()
        try:
            if target_key == "sent":
                # 发件客户端（iPhone）发完常会再 APPEND 一份到 Sent；提交服务
                # 已存过一次的，15 分钟内同收件人同主题同正文不再重复存。
                dup = conn.execute(
                    """SELECT id FROM sent_emails WHERE owner_email = ? AND recipient = ?
                       AND subject = ? AND body = ? AND timestamp > datetime('now', '-15 minutes')
                       ORDER BY id DESC LIMIT 1""",
                    (self.user_email, to_addr or "", subject, body),
                ).fetchone()
                if dup:
                    return dup["id"]
                cur = conn.execute(
                    "INSERT INTO sent_emails (owner_email, recipient, sender, subject, body, body_type, timestamp) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
                    (self.user_email, to_addr or "", sender, subject, body, body_type),
                )
                conn.commit()
                return cur.lastrowid
            if target_key == "drafts":
                cur = conn.execute(
                    "INSERT INTO draft_emails (owner_email, to_address, subject, body, html_body, editor_mode) VALUES (?, ?, ?, ?, ?, ?)",
                    (self.user_email, to_addr or "", subject,
                     "" if html_body else text_body, html_body,
                     "html" if html_body else "text"),
                )
                conn.commit()
                return cur.lastrowid
            # INBOX / Trash：按收信入库
            recipient = self.user_email
            if target_key == "trash":
                cur = conn.execute(
                    "INSERT INTO received_emails (recipient, sender, subject, body, body_type, message_id, is_read, is_deleted) VALUES (?, ?, ?, ?, ?, ?, 0, 1)",
                    (recipient, sender, subject, body, body_type, message_id),
                )
            else:
                cur = conn.execute(
                    "INSERT INTO received_emails (recipient, sender, subject, body, body_type, message_id) VALUES (?, ?, ?, ?, ?, ?)",
                    (recipient, sender, subject, body, body_type, message_id),
                )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


def build_tls_context():
    import os

    cert = os.environ.get("MAIL_IMAP_CERT") or os.environ.get("MAIL_SMTP_CERT") or ""
    key = os.environ.get("MAIL_IMAP_KEY") or os.environ.get("MAIL_SMTP_KEY") or ""
    if cert and key:
        import os.path

        if os.path.exists(cert) and os.path.exists(key):
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=cert, keyfile=key)
                return ctx
            except Exception as exc:
                print(f"[imap] 加载证书失败 {exc}，仅明文 143 可用")
    return None


async def run_imap_server():
    import logging
    import os

    logger = logging.getLogger("imap")
    tls_context = build_tls_context()
    host = os.environ.get("MAIL_IMAP_HOST", "0.0.0.0")
    plain_port = int(os.environ.get("MAIL_IMAP_PORT", "143"))
    tls_port = int(os.environ.get("MAIL_IMAPS_PORT", "993"))

    async def handler(reader, writer, tls_active=False):
        session = IMAPSession(reader, writer, tls_active, tls_context)
        try:
            await session.handle()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            logger.exception(f"IMAP 连接异常: {exc}")
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
    logger.info(f"IMAP 明文监听 {host}:{plain_port}（有证书时支持 STARTTLS）")
    if tls_context is not None:
        servers.append(await asyncio.start_server(
            lambda r, w: handler(r, w, tls_active=True), host, tls_port, ssl=tls_context
        ))
        logger.info(f"IMAPS 监听 {host}:{tls_port}")
    else:
        logger.warning("未配置证书，993 端口不监听；iPhone 请用 993 需先配证书，或 143 明文")
    async with servers[0]:
        await asyncio.gather(*[s.serve_forever() for s in servers])


def main():
    asyncio.run(run_imap_server())


if __name__ == "__main__":
    main()
