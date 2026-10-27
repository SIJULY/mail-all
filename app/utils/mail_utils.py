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
            r"(?<![a-zA-Z0-9])(\d{4,8})(?![a-zA-Z0-9])[^\n\r]{0,40}(?:is|为|是|就是|即为|作為|作为)[^\n\r]{0,20}(?:verification\s+code|authentication\s+code|security\s+code|one[- ]time\s+(?:code|password)|otp|验证码|驗證碼|验证代码|安全代码|一次性代码|一次性密碼|一次性密码|代码)",
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
    PARAGRAPH_TAGS = {
        "address", "article", "aside", "blockquote", "div", "dl", "fieldset",
        "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5",
        "h6", "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section",
        "table", "tbody", "tfoot", "thead", "tr", "ul",
    }
    CELL_TAGS = {"td", "th"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.skip_depth = 0
        self.hidden_depth = 0

    def _append_newline(self):
        if not self.parts or self.parts[-1] != "\n":
            self.parts.append("\n")

    def _append_blank_line(self):
        while self.parts and self.parts[-1] == " ":
            self.parts.pop()
        if not self.parts:
            return
        if len(self.parts) >= 2 and self.parts[-1] == "\n" and self.parts[-2] == "\n":
            return
        self._append_newline()
        self.parts.append("\n")

    def _append_inline_separator(self, separator=" "):
        if self.parts and self.parts[-1] not in {"\n", " ", "\t"}:
            self.parts.append(separator)

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
        if tag in self.CELL_TAGS:
            self._append_inline_separator(" ")
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
        if tag == "a":
            return
        if tag in self.CELL_TAGS:
            self._append_inline_separator(" ")
            return
        if tag in self.PARAGRAPH_TAGS:
            self._append_blank_line()
        elif tag in self.BLOCK_TAGS:
            self._append_newline()

    def handle_data(self, data):
        if self.skip_depth or self.hidden_depth:
            return
        data = str(data or "")
        if not data.strip():
            return
        normalized = re.sub(r"[\t \f\v\u00a0]+", " ", data)
        if self.parts and self.parts[-1] not in {"\n", " ", "\t"} and normalized[:1].strip():
            previous = str(self.parts[-1])[-1:]
            current = normalized[:1]
            if previous and current and re.match(r"[\w\u4e00-\u9fff]", previous) and re.match(r"[\w\u4e00-\u9fff]", current):
                self.parts.append(" ")
        self.parts.append(normalized)

    def get_text(self):
        return "".join(self.parts)


def _normalize_preview_text(text):
    text = html.unescape(str(text or "")).replace("\r\n", "\n").replace("\r", "\n")
    lines = []
    previous_non_empty = ""
    for raw_line in text.split("\n"):
        line = re.sub(r"[\t \f\v\u00a0]+", " ", raw_line).strip()
        line = re.sub(r"https?://\S+", "", line, flags=re.I).strip()
        line = re.sub(r"\s+([,.;:!?，。；：！？])", r"\1", line)
        line = re.sub(r"[（(]\s*[）)]", "", line).strip()
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

    normalized_text = str(text).replace("\r\n", "\n").replace("\r", "\n").strip()
    forwarded_marker = re.compile(r"-{2,}\s*Forwarded message\s*-{2,}", re.I)

    marker_match = forwarded_marker.search(normalized_text)
    # Telegram 通知本身已经单独显示收件人/发件人/主题；只要正文里存在标准转发头，
    # 预览应直接展示转发邮件的实际内容，而不是再次展示 From/Date/Subject。
    if marker_match:
        normalized_text = normalized_text[marker_match.start():]

    # HTML 清理后偶尔会把转发标记和 From/Date/Subject 挤在同一行，先补回换行。
    normalized_text = forwarded_marker.sub("--- Forwarded message ---\n", normalized_text, count=1)
    normalized_text = re.sub(
        r"\s+(?=(?:From|To|Cc|Date|Subject|Reply-To|发件人|收件人|日期|时间|主题)\s*:)",
        "\n",
        normalized_text,
        flags=re.I,
    )

    lines = normalized_text.split("\n")
    start = 0
    while start < len(lines) and not lines[start].strip():
        start += 1

    if start < len(lines) and re.match(r"^-{2,}\s*Forwarded message\s*-{2,}", lines[start].strip(), re.I):
        idx = start + 1
        header_pattern = re.compile(r"^(From|To|Cc|Date|Subject|Reply-To|发件人|收件人|日期|时间|主题)\s*:", re.I)
        subject_with_body_pattern = re.compile(
            r"^(?:Subject|主题)\s*:[^\n\r]*?\s+((?:\d{4,8}\s*(?:is|为|是|就是|即为|作為|作为).*)|(?:.*?(?:验证码|驗證碼|verification\s+code|security\s+code|otp).*?\d{4,8}.*))$",
            re.I,
        )
        while idx < len(lines):
            stripped = lines[idx].strip()
            if not stripped:
                idx += 1
                break
            if header_pattern.match(stripped):
                subject_with_body = subject_with_body_pattern.match(stripped)
                if subject_with_body:
                    lines[idx] = subject_with_body.group(1).strip()
                    break
                idx += 1
                continue
            break
        stripped_text = "\n".join(lines[idx:]).strip()
        # 如果转发标记后面只有 From/Date/Subject 等转发头、没有真正正文，
        # 也不能回退返回原文；否则 Telegram 预览会继续显示整段转发头。
        return stripped_text

    return normalized_text.strip()


def focus_preview_around_code(text, code=None, context_chars=900):
    """验证码邮件通知优先展示验证码附近内容，避免被转发头/品牌头图/说明文本挤掉。"""
    text = str(text or "").strip()
    if not text:
        return ""

    keyword_pattern = re.compile(
        r"验证码|驗證碼|验证代码|verification code|authentication code|security code|one[- ]time (?:code|password)|otp",
        re.I,
    )
    code = str(code or "").strip()
    if code:
        index = text.find(code)
        if index >= 0:
            prefix = text[:index]
            keyword_matches = list(keyword_pattern.finditer(prefix))
            if keyword_matches:
                keyword_start = keyword_matches[-1].start()
                # 从关键词所在段落开始，尽量保留“验证码”标签和相关说明。
                paragraph_start = prefix.rfind("\n\n", 0, keyword_start)
                line_start = prefix.rfind("\n", 0, keyword_start)
                if paragraph_start >= 0 and keyword_start - paragraph_start <= 500:
                    start = paragraph_start + 2
                elif line_start >= 0:
                    start = line_start + 1
                else:
                    start = max(0, keyword_start - 300)
            else:
                start = max(0, index - 300)
                line_start = text.find("\n", start, index)
                if line_start >= 0:
                    start = line_start + 1

            remaining_context = max(0, int(context_chars or 0) - len(text[start:index]))
            end = min(len(text), index + len(code) + remaining_context)
            focused = text[start:end].strip()
            return focused or text

    keyword_match = keyword_pattern.search(text)
    if keyword_match and keyword_match.start() > 500:
        line_start = text.rfind("\n", 0, keyword_match.start())
        start = 0 if line_start < 0 else line_start + 1
        return text[start:].strip() or text

    return text


_URL_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_\-+/=.%~&?#;]+$")


def strip_urls_for_telegram_preview(text: str) -> str:
    """Telegram 通知专用：把正文里的超链接折掉，只留链接文字。

    适用所有正文来源（HTML 去标签后、纯文本原样），不只修某一封：
    - ``文字 <https://…>``、``文字 (https://…)``、``文字 [https://…]``、
      ``文字（https://…）``、``[文字](https://…)`` 只留文字；
    - 裸网址、www. 开头的网址整段去掉；
    - 营销邮件纯文本版常把长跟踪链接折行，后续那些无空格的长 token 行
      （base64/跟踪参数续行）也一并去掉，否则只去第一行、续行还是一堆乱码；
    - 去网址后只剩 ``My Account:`` 这类空标签的行也去掉；
    - 去网址后残留的空方括号、行尾悬空的 ``[``、只剩分隔符的行也去掉。
    链接本身不丢失：通知末尾的“完整邮件”链接仍指向网页版原文。
    邮箱地址、验证码、普通句子不受影响（只匹配 http(s):// 和 www.）。
    """
    if not text:
        return ""
    normalized = str(text).replace("\r\n", "\n").replace("\r", "\n")
    # Markdown 链接先折成文字，避免括号里的网址被当成正文。
    normalized = re.sub(r"\[([^\]]+)\]\([^)]*https?://[^)]*\)", r"\1", normalized, flags=re.I)

    lines = normalized.split("\n")
    kept = []
    i = 0
    while i < len(lines):
        raw_line = lines[i]
        line = raw_line.strip()
        had_url = False

        def _remove_url(match):
            nonlocal had_url
            had_url = True
            return ""

        # 方括号、全角圆括号里的网址整段去掉。必须在裸网址之前：裸网址
        # 的 \S+ 会把收尾的 ]、）一起吃掉，只剩一个悬空的 [ —— 这就是
        # 通知里“账户栏 [”“桌面版 [ | iPhone 版 [”这类残渣的来源。
        line = re.sub(r"\[https?://[^\]\s]+\]", _remove_url, line, flags=re.I)
        line = re.sub(r"\[www\.[^\]\s]+\]", _remove_url, line, flags=re.I)
        line = re.sub(r"（https?://[^）\s]+）", _remove_url, line, flags=re.I)
        # 尖括号、圆括号里的网址整段去掉。
        line = re.sub(r"<https?://[^>\s]+>", _remove_url, line, flags=re.I)
        line = re.sub(r"\(https?://[^)\s]+\)", _remove_url, line, flags=re.I)
        # 裸网址、www. 网址。
        line = re.sub(r"https?://\S+", _remove_url, line, flags=re.I)
        line = re.sub(r"(?<![A-Za-z0-9])www\.\S+", _remove_url, line, flags=re.I)
        line = re.sub(r"\s+([，。；：！？,.;:!?])", r"\1", line).strip()
        line = re.sub(r"^[<>]+|[<>]+$", "", line).strip()
        line = re.sub(r"\(\s*\)", "", line).strip()
        # 去网址后残留的空方括号、行尾悬空的 [（已 mangled 的旧文本也顺手修掉）。
        line = re.sub(r"\[\s*\]", "", line).strip()
        line = re.sub(r"\[\s*$", "", line).strip()
        # 去网址后多出来的连续空格压成一个。
        line = re.sub(r" {2,}", " ", line).strip()
        # 只剩分隔符的行（原先全是链接，如社交图标那一行）直接不要。
        if re.fullmatch(r"[\s\[\]|·•\-–—/]+", line or ""):
            line = ""

        if had_url:
            # 去网址后只剩一个空标签（如 My Account:），整行不要。
            if re.fullmatch(r"[^:]{1,40}:", line):
                i += 1
                # 标签行后面的折行续行同样是网址碎片，一并跳过。
                while i < len(lines):
                    nxt = lines[i].strip()
                    if nxt and " " not in nxt and len(nxt) >= 20 and _URL_SAFE_TOKEN.match(nxt) and "@" not in nxt:
                        i += 1
                        continue
                    break
                continue
            kept.append(line)
            i += 1
            # 刚去过的长网址若在原文里被折行，后续无空格的长 token 行是它的续行。
            while i < len(lines):
                nxt = lines[i].strip()
                if nxt and " " not in nxt and len(nxt) >= 20 and _URL_SAFE_TOKEN.match(nxt) and "@" not in nxt:
                    i += 1
                    continue
                break
            continue

        kept.append(line)
        i += 1

    # 压掉多余空行，保留段落分隔。
    out_lines = []
    for line in kept:
        if not line:
            if out_lines and out_lines[-1] != "":
                out_lines.append("")
            continue
        out_lines.append(line)
    while out_lines and out_lines[-1] == "":
        out_lines.pop()
    return "\n".join(out_lines).strip()


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



# 转发/回复引用里允许保留的内联 CSS 属性。故意不含 position/z-index/
# top/left 等定位属性：引用内容嵌在写信编辑器里，定位样式可能盖住编辑器
# 本身；也不含 opacity/content 等可用来藏字或注入的属性。
_QUOTED_STYLE_PROPS = {
    "background", "background-color", "background-image", "background-repeat",
    "background-position", "background-size", "border", "border-top",
    "border-bottom", "border-left", "border-right", "border-color",
    "border-width", "border-style", "border-radius", "border-collapse",
    "border-spacing", "box-sizing", "color", "padding", "padding-top",
    "padding-bottom", "padding-left", "padding-right", "margin", "margin-top",
    "margin-bottom", "margin-left", "margin-right", "font", "font-family",
    "font-size", "font-weight", "font-style", "text-align", "text-decoration",
    "text-transform", "text-indent", "line-height", "letter-spacing",
    "word-spacing", "white-space", "word-break", "word-wrap", "overflow-wrap",
    "display", "width", "height", "max-width", "max-height", "min-width",
    "min-height", "vertical-align", "list-style", "list-style-type", "float",
    "clear", "outline", "outline-color", "outline-width", "outline-style",
}


def _parse_style_declarations(style_text: str):
    """把 style 属性 / CSS 规则体解析成 [(属性, 值)]，保序、去重后者为准。"""
    out = []
    seen = {}
    for chunk in (style_text or "").split(";"):
        if ":" not in chunk:
            continue
        prop, _, value = chunk.partition(":")
        prop = prop.strip().lower()
        value = value.strip()
        if not prop or not value:
            continue
        value = re.sub(r"\s*!important\s*$", "", value, flags=re.I).strip()
        if prop in seen:
            out[seen[prop]] = (prop, value)
        else:
            seen[prop] = len(out)
            out.append((prop, value))
    return out


def _filter_style_declarations(style_text: str) -> str:
    """只留白名单属性，并去掉危险的 url()/expression 之类声明。"""
    kept = []
    for prop, value in _parse_style_declarations(style_text):
        if prop not in _QUOTED_STYLE_PROPS:
            continue
        low = value.lower()
        if "expression(" in low or "javascript:" in low or "vbscript:" in low or "behavior" in low or "-moz-binding" in low:
            continue
        if "url(" in low:
            # 只放行 http(s) 图片/背景，data:/javascript: 等一律不要。
            if not re.search(r"url\(\s*['\"]?https?://", low):
                continue
        kept.append(f"{prop}: {value}")
    return "; ".join(kept)


def _protect_style_attributes(content: str) -> str:
    """bleach 未配 css_sanitizer 时会把 style 值清空（且服务器未必装
    tinycss2），所以进 bleach 前先把 style 暂存为 data-qstyle，出 bleach
    后再过滤还原。只改标签内的 style 属性，不动正文文本。"""

    def _repl(match):
        tag_head = match.group(1)
        value = match.group(3) if match.group(3) is not None else match.group(4)
        quote = '"' if match.group(3) is not None else "'"
        return f"{tag_head} data-qstyle={quote}{value or ''}{quote}"

    return re.sub(
        r"(<[^>]*?)\sstyle\s*=\s*(\"([^\"]*)\"|'([^']*)')",
        _repl,
        content,
    )


def _restore_style_attributes(content: str) -> str:
    def _repl(match):
        # 分组：1=整个带引号的值，2=双引号内，3=单引号内。
        raw = match.group(2) if match.group(2) is not None else match.group(3)
        filtered = _filter_style_declarations(html.unescape(raw or ""))
        if not filtered:
            return ""
        return f' style="{html.escape(filtered, quote=True)}"'

    return re.sub(
        r"\sdata-qstyle\s*=\s*(\"([^\"]*)\"|'([^']*)')",
        _repl,
        content,
    )


class _QuoteNode:
    __slots__ = ("tag", "attrs", "children", "parent", "text")

    def __init__(self, tag=None, attrs=None, parent=None, text=None):
        self.tag = tag
        self.attrs = dict(attrs or [])
        self.children = []
        self.parent = parent
        self.text = text


class _QuoteTreeParser(HTMLParser):
    _VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
             "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _QuoteNode(tag="root")
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = _QuoteNode(tag=tag, attrs=attrs, parent=self.stack[-1])
        self.stack[-1].children.append(node)
        if tag not in self._VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        node = _QuoteNode(tag=tag, attrs=attrs, parent=self.stack[-1])
        self.stack[-1].children.append(node)

    def handle_endtag(self, tag):
        for idx in range(len(self.stack) - 1, 0, -1):
            if self.stack[idx].tag == tag:
                del self.stack[idx:]
                break

    def handle_data(self, data):
        if data:
            self.stack[-1].children.append(_QuoteNode(parent=self.stack[-1], text=data))


def _iter_quote_elements(node):
    for child in node.children:
        if child.tag:
            yield child
            yield from _iter_quote_elements(child)


def _parse_simple_selector(part: str):
    """只支持 tag / .class / #id 及其组合，含 : [ * + ~ ( 等一律不支持。"""
    if not part or any(c in part for c in ":[]*+~()"):
        return None
    m = re.match(r"^([A-Za-z][\w-]*|\*)?", part)
    tag = m.group(1) or None
    rest = part[m.end():]
    classes, elem_id = set(), None
    for token in re.findall(r"[.#][A-Za-z_-][\w-]*", rest):
        if token.startswith("."):
            classes.add(token[1:])
        else:
            elem_id = token[1:]
    if rest and re.sub(r"[.#][A-Za-z_-][\w-]*", "", rest):
        return None
    return (tag, classes, elem_id)


def _simple_matches(node, simple):
    tag, classes, elem_id = simple
    if tag and tag != "*" and node.tag != tag:
        return False
    if elem_id and node.attrs.get("id") != elem_id:
        return False
    if classes:
        node_classes = set((node.attrs.get("class") or "").split())
        if not classes.issubset(node_classes):
            return False
    return True


def _selector_matches(node, selector: str) -> bool:
    """支持后代（空格）和子代（>），跳过伪类/属性选择器等复杂写法。"""
    tokens = re.findall(r">|[^>\s]+", selector)
    if not tokens:
        return False
    parts = []
    combinator = " "
    for token in tokens:
        if token == ">":
            combinator = ">"
            continue
        simple = _parse_simple_selector(token)
        if simple is None:
            return False
        parts.append((combinator, simple))
        combinator = " "
    current, idx = node, len(parts) - 1
    if not _simple_matches(current, parts[idx][1]):
        return False
    idx -= 1
    while idx >= 0:
        combinator, simple = parts[idx]
        if combinator == ">":
            current = current.parent
            if current is None or not current.tag or current.tag == "root":
                return False
            if not _simple_matches(current, simple):
                return False
        else:
            ancestor = current.parent
            while ancestor is not None and ancestor.tag not in (None, "root") and not _simple_matches(ancestor, simple):
                ancestor = ancestor.parent
            if ancestor is None or ancestor.tag in (None, "root"):
                return False
            current = ancestor
        idx -= 1
    return True


def _parse_css_rules(css_text: str):
    """解析样式块：跳过 @media/@font-face 等 @ 规则（含其嵌套块），
    只取普通规则。@media 里的移动端规则不内联——引用按桌面版排版走。"""
    text = re.sub(r"/\*.*?\*/", "", css_text or "", flags=re.S)
    rules, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n;":
            i += 1
        if i >= n:
            break
        if text[i] == "@":
            brace = text.find("{", i)
            semi = text.find(";", i)
            if brace == -1 or (semi != -1 and semi < brace):
                i = semi + 1 if semi != -1 else n
                continue
            depth, j = 1, brace + 1
            while j < n and depth:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            i = j
            continue
        brace = text.find("{", i)
        if brace == -1:
            break
        selectors = text[i:brace].strip()
        depth, j = 1, brace + 1
        while j < n and depth:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
            j += 1
        declarations = text[brace + 1:j - 1] if j > brace + 1 else ""
        if selectors and declarations.strip():
            rules.append((selectors, declarations))
        i = j
    return rules


def _serialize_quote_node(node) -> str:
    if node.tag is None:
        return html.escape(node.text or "", quote=False)
    attrs = "".join(f' {name}="{html.escape(value, quote=True)}"' for name, value in node.attrs.items())
    if node.tag in _QuoteTreeParser._VOID:
        return f"<{node.tag}{attrs}>"
    inner = "".join(_serialize_quote_node(child) for child in node.children)
    return f"<{node.tag}{attrs}>{inner}</{node.tag}>"


def _inline_quoted_styles(content: str, css_blocks):
    """把样式块规则转成内联 style，并把 class/id 重命名为 q- 前缀。

    返回 (内容, 是否成功)。重命名是为了后续样式隔离：q- 前缀的类名不会
    跟写信页本身的类名（如 .main）撞车。失败时原样返回并标记失败，
    调用方此时不得放行 class/id、也不得保留样式块，绝不阻塞转发。
    """
    try:
        rules = []
        for block in css_blocks:
            rules.extend(_parse_css_rules(block))
        parser = _QuoteTreeParser()
        parser.feed(content)
        elements = list(_iter_quote_elements(parser.root))
        rule_styles = {}
        for selectors, declarations in rules:
            parsed = _parse_style_declarations(declarations)
            if not parsed:
                continue
            for selector in selectors.split(","):
                selector = selector.strip()
                if not selector:
                    continue
                for element in elements:
                    if _selector_matches(element, selector):
                        merged = dict(rule_styles.get(id(element), []))
                        merged.update(dict(parsed))
                        rule_styles[id(element)] = list(merged.items())
        for element in elements:
            if id(element) in rule_styles:
                final = dict(rule_styles[id(element)])
                final.update(dict(_parse_style_declarations(element.attrs.get("style", ""))))
                element.attrs["style"] = "; ".join(f"{k}: {v}" for k, v in final.items())
            if element.attrs.get("class"):
                element.attrs["class"] = " ".join(
                    f"q-{token}" for token in element.attrs["class"].split() if token
                )
            if element.attrs.get("id"):
                element.attrs["id"] = f"q-{element.attrs['id']}"
        return "".join(_serialize_quote_node(child) for child in parser.root.children), True
    except Exception:
        return content, False


def _rename_selector_tokens(selector: str) -> str:
    """选择器里的 .class / #id 同步改成 q- 前缀，与树里的重命名对应。"""
    selector = re.sub(r"\.([A-Za-z_-][\w-]*)", r".q-\1", selector)
    selector = re.sub(r"#([A-Za-z_-][\w-]*)", r"#q-\1", selector)
    return selector


def _scope_selector(selector: str):
    """把一条选择器收窄到引用容器内；返回 None 表示该规则直接丢弃。"""
    selector = _rename_selector_tokens(selector.strip())
    if not selector or selector.startswith(".mail-quote-original"):
        return selector or None
    m = re.match(r"^(html|body)\b", selector)
    if m:
        return ".mail-quote-original" + selector[m.end():]
    if selector.startswith(":root"):
        return ".mail-quote-original" + selector[len(":root"):]
    if selector == "*" or selector.startswith("* ") or selector.startswith("*>"):
        return ".mail-quote-original *" + selector[1:]
    return f".mail-quote-original {selector}"


def _scope_rule_block(selectors: str, declarations: str):
    """一条普通规则的隔离版：选择器加前缀，声明过一遍白名单过滤。"""
    filtered = _filter_style_declarations(declarations)
    if not filtered:
        return None
    scoped = []
    for selector in selectors.split(","):
        scoped_selector = _scope_selector(selector)
        if scoped_selector:
            scoped.append(scoped_selector)
    if not scoped:
        return None
    return f"{', '.join(scoped)} {{ {filtered} }}"


def _scope_quoted_css(css_blocks) -> str:
    """把样式块隔离成只作用于引用容器的 CSS，失败或无内容时返回空串。

    保留 @font-face（字体名本身是唯一的，不会污染页面字体）和 @media
    里的规则（移动端/深色模式按容器内生效）；@import/@keyframes 等其他
    @ 规则一律丢弃。任一规则解析失败只丢该规则，不影响其余规则。
    """
    out = []
    for block in css_blocks:
        text = re.sub(r"/\*.*?\*/", "", block or "", flags=re.S)
        i, n = 0, len(text)
        while i < n:
            while i < n and text[i] in " \t\r\n;":
                i += 1
            if i >= n:
                break
            if text[i] == "@":
                header_end = text.find("{", i)
                semi = text.find(";", i)
                if header_end == -1 or (semi != -1 and semi < header_end):
                    i = semi + 1 if semi != -1 else n
                    continue
                header_raw = text[i:header_end].strip()
                header = header_raw.lower()
                depth, j = 1, header_end + 1
                while j < n and depth:
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                    j += 1
                inner = text[header_end + 1:j - 1] if j > header_end + 1 else ""
                i = j
                if header.startswith("@font-face"):
                    kept = []
                    for prop, value in _parse_style_declarations(inner):
                        if prop not in ("font-family", "src", "font-weight", "font-style", "font-display", "unicode-range"):
                            continue
                        if "javascript:" in value.lower() or "vbscript:" in value.lower():
                            continue
                        kept.append(f"{prop}: {value}")
                    if kept:
                        out.append(f"@font-face {{ {'; '.join(kept)} }}")
                elif header.startswith("@media"):
                    query = header_raw[len("@media"):].strip()
                    inner_rules = []
                    # 内层只按普通规则解析，不再嵌套 @ 规则。
                    for selectors, declarations in _parse_css_rules(inner):
                        scoped = _scope_rule_block(selectors, declarations)
                        if scoped:
                            inner_rules.append(scoped)
                    if query and inner_rules:
                        out.append(f"@media {query} {{ {' '.join(inner_rules)} }}")
                continue
            brace = text.find("{", i)
            if brace == -1:
                break
            selectors = text[i:brace].strip()
            depth, j = 1, brace + 1
            while j < n and depth:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            declarations = text[brace + 1:j - 1] if j > brace + 1 else ""
            i = j
            if selectors and declarations.strip():
                scoped = _scope_rule_block(selectors, declarations)
                if scoped:
                    out.append(scoped)
    return "\n".join(out)


def sanitize_quoted_html(html_content: str) -> str:
    """清洗回复/转发时引用的原邮件 HTML，使其可安全嵌入写信编辑器。

    目标是“引用后排版尽量接近原信”：表格、图片、内联样式都保留；
    样式块一律不直接留——先转成内联样式做兜底，再把样式块隔离成只
    作用于引用容器的 CSS（选择器加 .mail-quote-original 前缀，类名
    同步改成 q- 前缀，避免跟写信页本身的类名撞车），连同字体和媒体
    查询一起保留。这样原信的字体、深色模式、移动端规则在引用里仍
    生效，又不会污染写信页。最后仍由 bleach 白名单把关：script、
    事件属性、定位样式一律不进结果；内联转换失败时不放行 class/id、
    也不保留样式块，直接退回上一轮的安全版。未安装 bleach 时降级为
    全文转义。
    """
    content = html_content or ""
    css_blocks = re.findall(r"<style\b[^>]*>(.*?)</style\s*>", content, flags=re.I | re.S)
    # 整块删除：head（含标题/meta/样式）、body 里的 style、script。
    content = re.sub(r"<head\b[^>]*>.*?</head\s*>", "", content, flags=re.I | re.S)
    content = re.sub(r"<style\b[^>]*>.*?</style\s*>", "", content, flags=re.I | re.S)
    content = re.sub(r"<script\b[^>]*>.*?</script\s*>", "", content, flags=re.I | re.S)
    content, inline_ok = _inline_quoted_styles(content, css_blocks)
    scoped_css = _scope_quoted_css(css_blocks) if inline_ok else ""
    content = _protect_style_attributes(content)
    try:
        import bleach
    except ImportError:
        return html.escape(content)
    star_attrs = ["title", "data-qstyle", "align", "valign", "width",
                  "height", "bgcolor", "border", "cellpadding", "cellspacing",
                  "colspan", "rowspan", "color", "face", "size"]
    if scoped_css:
        # 只有内联转换成功时，内容里的 class/id 才全是 q- 前缀，
        # 此时放行它们才安全；否则一律不放行。
        star_attrs = star_attrs + ["class", "id"]
    cleaned = bleach.clean(
        content,
        tags=[
            "a", "b", "blockquote", "br", "caption", "center", "code",
            "col", "colgroup", "div", "em", "font", "h1", "h2", "h3", "h4",
            "hr", "i", "img", "li", "ol", "p", "pre", "span", "strong",
            "table", "tbody", "td", "tfoot", "th", "thead", "tr", "u", "ul",
        ],
        attributes={
            "a": ["href", "target"],
            "img": ["src", "alt"],
            "*": star_attrs,
        },
        protocols=["http", "https", "mailto"],
        strip=True,
        strip_comments=True,
    )
    cleaned = _restore_style_attributes(cleaned)
    if scoped_css:
        return f"<style>{scoped_css}</style><div class=\"mail-quote-original\">{cleaned}</div>"
    return cleaned



def quote_text_as_html(text: str) -> str:
    """将纯文本按行转义为 HTML，并加上 '>' 引用前缀。"""
    return "<br>".join(f"&gt; {html.escape(line)}" for line in (text or "").splitlines())
