"""邮件工具模块。"""

import html
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
    # 避免把纯数字日期/编号片段误识别为验证码，例如 2026-08
    return bool(re.search(r"[A-Z]", value, re.IGNORECASE))



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
            if _is_likely_hyphenated_alnum_code(code):
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
