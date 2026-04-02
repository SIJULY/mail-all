"""邮件工具模块。"""

import random
import re
import string


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

    if any(keyword in body_lower for keyword in code_keywords):
        semantic_patterns = [
            r"(?:your\s+chatgpt\s+code\s+is|your\s+code\s+is|verification\s+code|temporary\s+verification\s+code|authentication\s+code|log-?in\s+code|login\s+code|otp)[^\d]{0,30}(\d{6})",
        ]
        for pat in semantic_patterns:
            m = re.search(pat, body_text, re.IGNORECASE)
            if m:
                return m.group(1)

    m = re.search(r"(?<!\d)(\d{6})(?!\d)", body_text)
    if m:
        return m.group(1)

    m = re.search(r"\b(\d{4,8})\b", body_text)
    if m:
        return m.group(1)

    return None



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
