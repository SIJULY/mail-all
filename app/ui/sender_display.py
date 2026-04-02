"""发件人显示辅助模块。"""

from email.utils import parseaddr

_PERSONAL_PROVIDER_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "live.com",
    "hotmail.com",
    "hotmail.co.jp",
    "outlook.jp",
}


def guess_sender_brand(email_addr: str, brand_map: dict) -> str:
    email_addr = (email_addr or "").strip().lower()
    if "@" not in email_addr:
        return ""
    domain = email_addr.split("@", 1)[1]
    if domain in brand_map:
        return brand_map[domain]
    for mapped_domain, brand in brand_map.items():
        if domain.endswith("." + mapped_domain):
            return brand
    return ""



def build_sender_display(sender_raw: str, brand_map: dict):
    sender_raw = (sender_raw or "").strip()
    sender_name, sender_email = parseaddr(sender_raw)
    display_name = (sender_name or "").strip()
    display_email = (sender_email or "").strip()
    brand_name = guess_sender_brand(display_email or sender_raw, brand_map)
    email_domain = display_email.split("@", 1)[1].lower() if "@" in display_email else ""

    if display_name:
        list_text = display_name
    elif display_email and email_domain in _PERSONAL_PROVIDER_DOMAINS:
        list_text = display_email
    else:
        list_text = brand_name or display_email or sender_raw

    detail_text = sender_raw or list_text
    if display_email and not display_name and brand_name and email_domain not in _PERSONAL_PROVIDER_DOMAINS:
        detail_text = f"{brand_name} <{display_email}>"
    return list_text, detail_text
