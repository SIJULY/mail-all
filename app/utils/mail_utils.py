"""邮件工具模块。"""

import html
from html.parser import HTMLParser
import random
import re
import string


def _is_likely_year_token(value: str) -> bool:
    value = str(value or "").strip()
    return len(value) == 4 and value.isdigit() and 1900 <= int(value) <= 2099



def _is_likely_hyphenated_alnum_code(value: str) -> bool:
    value = str(value or "").strip()
    if not re.fullmatch(r"[A-Z0-9]{2,6}-[A-Z0-9]{2,6}", value, re.IGNORECASE):
        return False
    # 避免匹配到邮箱前缀（比如以字母结尾并可能会跟随 @）
    # 或者类似 salsa-65 这种
    
    # 首先，如果是纯数字日期/编号片段，避免误识别为验证码，例如 2026-08
    has_alpha = bool(re.search(r"[A-Z]", value, re.IGNORECASE))
    if not has_alpha:
        return False
        
    return True



def extract_code_from_body(body_text):
    if not body_text:
        return None

    body_text = str(body_text)
    body_lower = body_text.lower()
    code_keywords = [
        "verification code",
        "验证码",
        "驗證碼",
        "検証コード",
        "authentication code",
        "your code is",
        "your code:",
        "your code",
        "code below",
        "use the code below",
        "code is",
        "code:",
        "chatgpt code",
        "temporary verification code",
        "enter this temporary verification code",
        "log-in code",
        "login code",
        "one-time password",
        "one time password",
        "one-time code",
        "one time code",
        "otp",
        "security code",
        "passcode",
        "confirmation code",
        "auth code",
        "一次性代码",
        "一次性密碼",
        "一次性密码",
        "验证代码",
        "授权码",
        "校验码",
        "确认码",
        "激活码",
        "登录码",
        "登入碼",
        "安全代码",
    ]
    has_code_keyword = any(keyword in body_lower for keyword in code_keywords)

    if has_code_keyword:
        semantic_patterns = [
            r"(?:your\s+chatgpt\s+code\s+is|your\s+code\s+is|verification\s+code|temporary\s+verification\s+code|authentication\s+code|confirmation\s+code|log-?in\s+code|login\s+code|otp|security\s+code|passcode|auth\s+code|安全代码|一次性代码|一次性密碼|一次性密码|one-time\s+code|one\s+time\s+code|one-time\s+password)[^A-Z0-9]{0,40}([A-Z0-9]{2,6}-[A-Z0-9]{2,6})",
            r"(?:use\s+the\s+code\s+below|code\s+below)[\s\S]{0,120}?([A-Z0-9]{2,6}-[A-Z0-9]{2,6})",
            r"(?:code|验证码|驗證碼|検証コード|otp|授权码|校验码|确认码|激活码|登录码|登入碼|代码)[^A-Z0-9]{0,20}([A-Z0-9]{2,6}-[A-Z0-9]{2,6})",
            r"(?:your\s+chatgpt\s+code\s+is|your\s+code\s+is|verification\s+code|temporary\s+verification\s+code|authentication\s+code|log-?in\s+code|login\s+code|otp|security\s+code|安全代码|一次性代码|一次性密碼|一次性密码|one-time\s+code|one\s+time\s+code|one-time\s+password)[^\d]{0,30}(\d{4,8})",
            r"(?:code|验证码|驗證碼|検証コード|otp|授权码|校验码|确认码|激活码|登录码|登入碼|代码)[^\d]{0,12}(\d{4,8})",
        ]
        for pat in semantic_patterns:
            m = re.search(pat, body_text, re.IGNORECASE)
            if m:
                code = m.group(1)
                if "-" in code and _is_likely_hyphenated_alnum_code(code):
                    return code.upper()
                if not _is_likely_year_token(code):
                    return code

        # fallback: support verification codes like 8QU-J6E / AB12-CD34 when the
        # email contains a code keyword but the exact wording is not covered above.
        m = re.search(r"(?<![A-Z0-9])([A-Z0-9]{2,6}-[A-Z0-9]{2,6})(?![A-Z0-9])", body_text, re.IGNORECASE)
        if m:
            code = m.group(1)
            # Ensure it's not part of an email address (e.g. salsa-65@cloud.com)
            start_pos = m.start(1)
            end_pos = m.end(1)
            is_email_part = False
            if end_pos < len(body_text) and body_text[end_pos] == '@':
                is_email_part = True
                
            if not is_email_part and _is_likely_hyphenated_alnum_code(code):
                return code.upper()

        # fallback: find 6 digits not surrounded by letters or digits (to prevent matching UUIDs like 5c896924)
        m = re.search(r"(?<![a-zA-Z0-9])(\d{6})(?![a-zA-Z0-9])", body_text)
        if m:
            code = m.group(1)
            if not _is_likely_year_token(code):
                return code

    return None



def linkify_plain_text(text: str) -> str:
    raw_text = str(text or "")
    escaped_text = html.escape(raw_text)
    url_pattern = re.compile(r"(?P<url>(?:https?://|www\.)[^\s<]+)", re.IGNORECASE)

    def replace_match(match):
        display_url = match.group("url")
        trailing = ""
        while display_url and display_url[-1] in r".,;:!?)\]}":
            trailing = display_url[-1] + trailing
            display_url = display_url[:-1]
        href = display_url if display_url.lower().startswith(("http://", "https://")) else f"https://{display_url}"
        return f'<a href="{href}" target="_blank" rel="noopener noreferrer">{display_url}</a>{trailing}'

    linked_text = url_pattern.sub(replace_match, escaped_text)
    return linked_text.replace("\n", "<br>")



class _HTMLPreviewParser(HTMLParser):
    """把 HTML 邮件转换成适合通知预览的纯文本。"""

    BLOCK_TAGS = {
        "address", "article", "aside", "blockquote", "div", "dl", "dt", "dd",
        "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2", "h3",
        "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p",
        "pre", "section", "table", "tbody", "td", "tfoot", "th", "thead", "tr", "ul",
    }
    SKIP_TAGS = {"script", "style", "head", "title", "meta", "noscript", "svg", "canvas"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip_depth = 0
        self.hidden_depth = 0

    def _append_newline(self):
        if not self.parts or self.parts[-1] != "\n":
            self.parts.append("\n")

    def _is_hidden(self, attrs):
        attrs_dict = {str(k).lower(): str(v or "").lower() for k, v in attrs}
        if "hidden" in attrs_dict or attrs_dict.get("aria-hidden") == "true":
            return True
        style = re.sub(r"\s+", "", attrs_dict.get("style", ""))
        hidden_style_tokens = [
            "display:none",
            "visibility:hidden",
            "opacity:0",
            "font-size:0",
            "max-height:0",
            "height:0",
            "width:0",
        ]
        return any(token in style for token in hidden_style_tokens)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.skip_depth:
            self.skip_depth += 1
            return
        if self.hidden_depth:
            self.hidden_depth += 1
            return
        if tag in self.SKIP_TAGS:
            self.skip_depth = 1
            return
        if self._is_hidden(attrs):
            self.hidden_depth = 1
            return
        # 图片 alt 文本在邮件通知里经常重复标题或品牌名，直接忽略图片节点。
        if tag == "img":
            return
        if tag in {"br", "hr"} or tag in self.BLOCK_TAGS:
            self._append_newline()

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip_depth:
            self.skip_depth -= 1
            return
        if self.hidden_depth:
            self.hidden_depth -= 1
            return
        if tag in self.BLOCK_TAGS:
            self._append_newline()

    def handle_data(self, data):
        if self.skip_depth or self.hidden_depth:
            return
        data = str(data or "")
        if not data.strip():
            return
        self.parts.append(data)

    def get_text(self):
        return "".join(self.parts)


def _normalize_preview_text(text):
    text = html.unescape(str(text or "")).replace("\r\n", "\n").replace("\r", "\n")
    lines = []
    previous_non_empty = ""
    for raw_line in text.split("\n"):
        line = re.sub(r"[\t \f\v\u00a0]+", " ", raw_line).strip()
        if not line:
            if lines and lines[-1] != "":
                lines.append("")
            continue
        # 去掉邮件模板里常见的连续重复标题/alt 文本。
        if line == previous_non_empty:
            continue
        lines.append(line)
        previous_non_empty = line

    normalized = "\n".join(lines).strip()
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    return normalized


def strip_forwarded_headers_for_preview(text):
    """移除预览开头的转发头，避免 Telegram 通知重复显示 From/Date/Subject。"""
    if not text:
        return ""

    lines = str(text).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    start = 0
    while start < len(lines) and not lines[start].strip():
        start += 1

    if start < len(lines) and re.match(r"^-{2,}\s*Forwarded message\s*-{2,}", lines[start].strip(), re.I):
        idx = start + 1
        header_pattern = re.compile(r"^(From|To|Cc|Date|Subject|Reply-To|发件人|收件人|日期|时间|主题)\s*:", re.I)
        while idx < len(lines):
            stripped = lines[idx].strip()
            if not stripped:
                idx += 1
                break
            if header_pattern.match(stripped):
                idx += 1
                continue
            break
        stripped_text = "\n".join(lines[idx:]).strip()
        if stripped_text:
            return stripped_text

    return str(text).strip()


def strip_tags_for_telegram_preview(html_content):
    """把 HTML 邮件转换成适合 Telegram 通知的纯文本，保留必要换行。"""
    if not html_content:
        return ""
    parser = _HTMLPreviewParser()
    try:
        parser.feed(str(html_content))
        parser.close()
        return _normalize_preview_text(parser.get_text())
    except Exception:
        text_content = re.sub(r"<style.*?</style>|<script.*?</script>|<[^>]+>", "\n", str(html_content), flags=re.S | re.I)
        return _normalize_preview_text(text_content)


def strip_tags_for_preview(html_content):
    if not html_content:
        return ""
    text_content = re.sub(r"<style.*?</style>|<script.*?</script>|<[^>]+>", " ", str(html_content), flags=re.S)
    return re.sub(r"\s+", " ", text_content).strip()



def normalize_email_address(value: str) -> str:
    return str(value or "").strip().lower()



def normalize_domain(value: str) -> str:
    return str(value or "").strip().lower().lstrip("@").strip()



def generate_local_part(length: int = 10) -> str:
    length = max(4, min(int(length or 10), 32))
    prefix = "".join(random.choices(string.ascii_lowercase, k=max(3, length - 3)))
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=3))
    return (prefix + suffix)[:length]



def generate_subdomain_label(min_length: int = 3, max_length: int = 5) -> str:
    min_length = max(1, int(min_length or 3))
    max_length = max(min_length, int(max_length or 5))
    length = random.randint(min_length, max_length)
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
