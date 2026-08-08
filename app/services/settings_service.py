"""设置与域名选择服务模块。"""

import random
from typing import Any, Dict

from app.repositories.mail_repo import get_enabled_domain_rows, get_primary_domain_row, materialize_domain_for_mailbox
from app.utils.mail_utils import generate_subdomain_label, normalize_domain


def get_moemail_config_domains():
    primary_row = get_primary_domain_row()
    if primary_row and primary_row["domain"]:
        return [normalize_domain(primary_row["domain"])]
    managed_domains = [normalize_domain(row["domain"]) for row in get_enabled_domain_rows()]
    return managed_domains if managed_domains else ["example.com"]



def choose_moemail_domain(requested_domain: str) -> str:
    return choose_moemail_address_plan(requested_domain)["domain"]



def choose_moemail_address_plan(requested_domain: str) -> Dict[str, Any]:
    requested_domain = normalize_domain(requested_domain)
    enabled_rows = get_enabled_domain_rows()
    primary_row = get_primary_domain_row()
    primary_domain = normalize_domain(primary_row["domain"]) if primary_row and primary_row["domain"] else ""

    if requested_domain and primary_row and primary_domain and requested_domain == primary_domain:
        plus_alias_provider = normalize_domain(primary_row["plus_alias_provider"])
        plus_alias_local_part = (primary_row["plus_alias_local_part"] or "").strip().lower()
        if plus_alias_provider and plus_alias_local_part:
            return {
                "mode": "plus_alias",
                "domain": plus_alias_provider,
                "base_local_part": plus_alias_local_part,
                "provider": plus_alias_provider,
                "requested_domain": requested_domain,
                "primary_domain": primary_domain,
            }
        if enabled_rows:
            selected_row = random.choice(enabled_rows)
            return {
                "mode": "domain",
                "domain": materialize_domain_for_mailbox(selected_row) or requested_domain,
                "base_local_part": "",
                "provider": "",
                "requested_domain": requested_domain,
                "primary_domain": primary_domain,
            }

    if requested_domain:
        for row in enabled_rows:
            if normalize_domain(row["domain"]) == requested_domain:
                return {
                    "mode": "domain",
                    "domain": materialize_domain_for_mailbox(row) or requested_domain,
                    "base_local_part": "",
                    "provider": "",
                    "requested_domain": requested_domain,
                    "primary_domain": primary_domain,
                }
        return {
            "mode": "domain",
            "domain": requested_domain,
            "base_local_part": "",
            "provider": "",
            "requested_domain": requested_domain,
            "primary_domain": primary_domain,
        }

    if enabled_rows:
        selected_row = enabled_rows[0]
        return {
            "mode": "domain",
            "domain": materialize_domain_for_mailbox(selected_row) or normalize_domain(selected_row["domain"]),
            "base_local_part": "",
            "provider": "",
            "requested_domain": requested_domain,
            "primary_domain": primary_domain,
        }

    return {
        "mode": "domain",
        "domain": "example.com",
        "base_local_part": "",
        "provider": "",
        "requested_domain": requested_domain,
        "primary_domain": primary_domain,
    }



def build_moemail_address(name: str, requested_domain: str) -> str:
    plan = choose_moemail_address_plan(requested_domain)
    if plan["mode"] == "plus_alias":
        alias_suffix = generate_subdomain_label(3, 5)
        return f"{plan['base_local_part']}+{alias_suffix}@{plan['domain']}"
    return f"{name}@{plan['domain']}"


__all__ = ["build_moemail_address", "choose_moemail_address_plan", "choose_moemail_domain", "get_moemail_config_domains"]

# step3 plus alias generation marker
