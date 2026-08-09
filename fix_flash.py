import re

with open("app/ui/page_builders.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update CSS
old_css = """.flash-success,.flash-error{padding:14px 16px;margin-bottom:14px;border-radius:16px;border:1px solid transparent;transition:opacity .5s ease;box-shadow:0 6px 18px rgba(15,23,42,0.04);font-weight:700;} .flash-success{background:#ecfdf3;color:#166534;border-color:#bbf7d0;} .flash-error{background:#fef2f2;color:#991b1b;border-color:#fecaca;}"""
new_css = """.flash-container{position:fixed;top:24px;left:50%;transform:translateX(-50%);z-index:9999;display:flex;flex-direction:column;gap:12px;pointer-events:none;} .flash-success,.flash-error{padding:14px 24px;border-radius:999px;border:1px solid transparent;transition:opacity .4s ease, transform .4s cubic-bezier(0.16, 1, 0.3, 1);box-shadow:0 10px 30px rgba(15,23,42,0.12);font-weight:800;font-size:14px;pointer-events:auto;animation:flashSlideIn .4s cubic-bezier(0.16, 1, 0.3, 1) forwards;} @keyframes flashSlideIn{from{opacity:0;transform:translateY(-20px) scale(0.95);}to{opacity:1;transform:translateY(0) scale(1);}} .flash-success{background:#ecfdf3;color:#166534;border-color:#bbf7d0;} .flash-error{background:#fef2f2;color:#991b1b;border-color:#fecaca;}"""
content = content.replace(old_css, new_css)


# 2. Move flash messages element out of the content div, into a flash-container
old_html = """</div></div><div class="content">{% with messages = get_flashed_messages(with_categories=true) %}{% for category, message in messages %}<div class="flash-{{ category }}">{{ message }}</div>{% endfor %}{% endwith %}"""
new_html = """</div></div><div class="flash-container">{% with messages = get_flashed_messages(with_categories=true) %}{% for category, message in messages %}<div class="flash-{{ category }}">{{ message }}</div>{% endfor %}{% endwith %}</div><div class="content">"""
content = content.replace(old_html, new_html)


with open("app/ui/page_builders.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Flash UI fixed.")