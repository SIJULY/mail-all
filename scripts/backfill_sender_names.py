#!/usr/bin/env python3
"""按常见品牌域名回填历史邮件 sender 显示名。"""

import os
import sqlite3
from email.utils import parseaddr

DB_PATH = os.environ.get("MAIL_DB_FILE", "/opt/mail_api/emails.db")

BRAND_MAP = {
    "tm.openai.com": "OpenAI",
    "openai.com": "OpenAI",
    "chatgpt.com": "OpenAI",
    "auth.openai.com": "OpenAI",
    "google.com": "Google",
    "accounts.google.com": "Google",
    "googlemail.com": "Google",
    "youtube.com": "YouTube",
    "android.com": "Android",
    "gmail.com": "Gmail",
    "facebookmail.com": "Facebook",
    "facebook.com": "Facebook",
    "meta.com": "Meta",
    "instagram.com": "Instagram",
    "threads.net": "Threads",
    "whatsapp.com": "WhatsApp",
    "messenger.com": "Messenger",
    "x.com": "X",
    "twitter.com": "X",
    "t.co": "X",
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    "github.net": "GitHub",
    "gitlab.com": "GitLab",
    "bitbucket.org": "Bitbucket",
    "microsoft.com": "Microsoft",
    "live.com": "Microsoft",
    "outlook.com": "Outlook",
    "office.com": "Microsoft 365",
    "office365.com": "Microsoft 365",
    "skype.com": "Skype",
    "teams.microsoft.com": "Microsoft Teams",
    "apple.com": "Apple",
    "icloud.com": "iCloud",
    "me.com": "iCloud",
    "amazon.com": "Amazon",
    "amazonaws.com": "AWS",
    "aws.amazon.com": "AWS",
    "primevideo.com": "Prime Video",
    "paypal.com": "PayPal",
    "stripe.com": "Stripe",
    "wise.com": "Wise",
    "binance.com": "Binance",
    "coinbase.com": "Coinbase",
    "telegram.org": "Telegram",
    "telegram.me": "Telegram",
    "discord.com": "Discord",
    "discordapp.com": "Discord",
    "slack.com": "Slack",
    "notion.so": "Notion",
    "figma.com": "Figma",
    "canva.com": "Canva",
    "adobe.com": "Adobe",
    "dropbox.com": "Dropbox",
    "box.com": "Box",
    "zoom.us": "Zoom",
    "airbnb.com": "Airbnb",
    "booking.com": "Booking.com",
    "uber.com": "Uber",
    "lyftmail.com": "Lyft",
    "netflix.com": "Netflix",
    "spotify.com": "Spotify",
    "tiktok.com": "TikTok",
    "snapchat.com": "Snapchat",
    "pinterest.com": "Pinterest",
    "redditmail.com": "Reddit",
    "reddit.com": "Reddit",
    "quora.com": "Quora",
    "medium.com": "Medium",
    "substack.com": "Substack",
    "mailchimp.com": "Mailchimp",
    "sendgrid.net": "SendGrid",
    "brevo.com": "Brevo",
    "mailgun.org": "Mailgun",
    "hubspotemail.net": "HubSpot",
    "hubspot.com": "HubSpot",
    "zendesk.com": "Zendesk",
    "atlassian.com": "Atlassian",
    "jira.com": "Jira",
    "confluence.net": "Confluence",
    "shopify.com": "Shopify",
    "nike.com": "Nike",
    "steamcommunity.com": "Steam",
    "steampowered.com": "Steam",
    "epicgames.com": "Epic Games",
    "ea.com": "EA",
    "riotgames.com": "Riot Games",
    "supercell.com": "Supercell",
    "mi.com": "Xiaomi",
    "xiaomi.com": "Xiaomi",
    "huawei.com": "Huawei",
    "samsung.com": "Samsung",
    "cloudns.net": "ClouDNS",
    "namecheap.com": "Namecheap",
    "godaddy.com": "GoDaddy",
    "cloudflare.com": "Cloudflare",
    "vercel.com": "Vercel",
    "render.com": "Render",
    "railway.app": "Railway",
    "digitalocean.com": "DigitalOcean",
}


def guess_brand(email_addr: str) -> str:
    email_addr = (email_addr or "").strip().lower()
    if "@" not in email_addr:
        return ""
    domain = email_addr.split("@", 1)[1]
    if domain in BRAND_MAP:
        return BRAND_MAP[domain]
    for mapped_domain, brand in BRAND_MAP.items():
        if domain.endswith("." + mapped_domain):
            return brand
    return ""



def main() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT id, sender FROM received_emails ORDER BY id ASC").fetchall()
    updated = 0
    for row in rows:
        sender_raw = (row["sender"] or "").strip()
        if not sender_raw:
            continue
        sender_name, sender_email = parseaddr(sender_raw)
        if sender_name.strip():
            continue
        brand = guess_brand(sender_email or sender_raw)
        if not brand or not sender_email:
            continue
        new_sender = f"{brand} <{sender_email}>"
        conn.execute("UPDATE received_emails SET sender = ? WHERE id = ?", (new_sender, row["id"]))
        updated += 1
    conn.commit()
    conn.close()
    print(f"Updated sender rows: {updated}")


if __name__ == "__main__":
    main()
