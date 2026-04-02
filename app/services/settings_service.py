"""设置与域名选择服务模块。"""

import random

from app.repositories.mail_repo import get_enabled_domain_rows, get_primary_domain_row, materialize_domain_for_mailbox
from app.utils.mail_utils import normalize_domain


def get_moemail_config_domains():
    primary_row = get_primary_domain_row()
    if primary_row and primary_row["domain"]:
        return [normalize_domain(primary_row["domain"])]
    managed_domains = [normalize_domain(row["domain"]) for row in get_enabled_domain_rows()]
    return managed_domains if managed_domains else ["example.com"]



def choose_moemail_domain(requested_domain: str) -> str:
    requested_domain = normalize_domain(requested_domain)
    enabled_rows = get_enabled_domain_rows()
    primary_row = get_primary_domain_row()
    primary_domain = normalize_domain(primary_row["domain"]) if primary_row and primary_row["domain"] else ""

    if requested_domain and primary_domain and requested_domain == primary_domain and enabled_rows:
        return materialize_domain_for_mailbox(random.choice(enabled_rows)) or requested_domain

    if requested_domain:
        for row in enabled_rows:
            if normalize_domain(row["domain"]) == requested_domain:
                return materialize_domain_for_mailbox(row) or requested_domain
        return requested_domain

    if enabled_rows:
        return materialize_domain_for_mailbox(enabled_rows[0]) or normalize_domain(enabled_rows[0]["domain"])

    return "example.com"


__all__ = ["choose_moemail_domain", "get_moemail_config_domains"]
