"""设置与域名选择服务模块。"""

from app.repositories.mail_repo import get_managed_domains
from app.utils.mail_utils import normalize_domain


def choose_moemail_domain(requested_domain: str) -> str:
    requested_domain = normalize_domain(requested_domain)
    managed_domains = [normalize_domain(row["domain"]) for row in get_managed_domains(include_inactive=False)]

    if requested_domain:
        return requested_domain

    if managed_domains:
        return managed_domains[0]

    return "example.com"
