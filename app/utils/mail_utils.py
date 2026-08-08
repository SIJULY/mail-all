"""邮件工具模块。"""

import html
import random
import re
import string


def _is_likely_year_token(value: str) -> bool:
    value = str(value or "").strip()
    return len(value) == 4 and value.isdigit() and 1900 <= int(value) <= 2099



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
        "chatgpt code",
        "temporary verification code",
        "enter this temporary verification code",
        "log-in code",
        "login code",
        "one-time password",
        "otp",
    ]
    has_code_keyword = any(keyword in body_lower for keyword in code_keywords)

    if has_code_keyword:
        semantic_patterns = [
            r"(?:your\s+chatgpt\s+code\s+is|your\s+code\s+is|verification\s+code|temporary\s+verification\s+code|authentication\s+code|log-?in\s+code|login\s+code|otp)[^\d]{0,30}(\d{4,8})",
            r"(?:code|验证码|驗證碼|検証コード|otp)[^\d]{0,12}(\d{4,8})",
        ]
        for pat in semantic_patterns:
            m = re.search(pat, body_text, re.IGNORECASE)
            if m:
                code = m.group(1)
                if not _is_likely_year_token(code):
                    return code

    m = re.search(r"(?<!\d)(\d{6})(?!\d)", body_text)
    if m:
        return m.group(1)

    return None



def linkify_plain_text(text: str) -> str:
    raw_text = str(text or "")
    escaped_text = html.escape(raw_text)
    url_pattern = re.compile(r"(?P<url>(?:https?://|www\.)[^\s<]+)", re.IGNORECASE)

    def replace_match(match):
        display_url = match.group("url")
        trailing = ""
        while display_url and display_url[-1] in ".,;:!?)\]}":
            trailing = display_url[-1] + trailing
            display_url = display_url[:-1]
        href = display_url if display_url.lower().startswith(("http://", "https://")) else f"https://{display_url}"
        return f'<a href="{href}" target="_blank" rel="noopener noreferrer">{display_url}</a>{trailing}'

    linked_text = url_pattern.sub(replace_match, escaped_text)
    return linked_text.replace("\n", "<br>")



def strip_tags_for_preview(html_content):
    if not html_content:
        return ""
    text_content = re.sub(r"<style.*?</style>|<script.*?</script>|<[^>]+>", " ", html_content, flags=re.S)
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
