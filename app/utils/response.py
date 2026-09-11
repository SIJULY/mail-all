"""响应与分页辅助模块。"""

from typing import Any

from app.constants import EMAILS_PER_PAGE, EMAILS_PER_PAGE_OPTIONS


def get_valid_per_page(value: Any) -> int:
    try:
        per_page = int(value)
    except Exception:
        per_page = EMAILS_PER_PAGE
    if per_page not in EMAILS_PER_PAGE_OPTIONS:
        per_page = EMAILS_PER_PAGE
    return per_page
