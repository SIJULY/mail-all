with open("app/ui/page_builders.py", "r", encoding="utf-8") as f:
    content = f.read()

# Replace CSS
content = content.replace(
    '.mail-flag-btn svg{width:18px;height:18px;display:block;fill:currentColor;}',
    '.mail-flag-btn svg{width:18px;height:18px;display:block;}'
)
content = content.replace(
    '.icon-btn[data-tooltip]:hover::after{content:attr(data-tooltip);position:absolute;top:100%;left:50%;transform:translateX(-50%) translateY(6px);background:rgba(15,23,42,.9);color:#fff;padding:5px 8px;border-radius:6px;font-size:12px;white-space:nowrap;z-index:1000;pointer-events:none;opacity:1;}',
    '.icon-btn[data-tooltip]:hover::after{content:attr(data-tooltip);position:absolute;top:100%;left:50%;transform:translateX(-50%) translateY(6px);background:rgba(15,23,42,.9);color:#fff;padding:5px 8px;border-radius:6px;font-size:12px;white-space:nowrap;z-index:1000;pointer-events:none;opacity:1;}' # Wait, delay is not here. 
)

# Replace star button
star_search = '<button type="submit" form="delete-selected-form" formaction="{{ mail.toggle_star_url }}" formmethod="post" class="mail-flag-btn {% if mail.is_starred %}active-star{% endif %}" title="{% if mail.is_starred %}取消星标{% else %}设为星标{% endif %}">★</button>'
star_replace = '<button type="submit" form="delete-selected-form" formaction="{{ mail.toggle_star_url }}" formmethod="post" class="mail-flag-btn icon-btn {% if mail.is_starred %}active-star{% endif %}" data-tooltip="{% if mail.is_starred %}取消星标{% else %}设为星标{% endif %}"><svg viewBox="0 0 24 24" fill="{% if mail.is_starred %}#eab308{% else %}none{% endif %}" stroke="{% if mail.is_starred %}#eab308{% else %}currentColor{% endif %}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg></button>'
if star_search in content:
    content = content.replace(star_search, star_replace)

# Replace important button
important_search = '<button type="submit" form="delete-selected-form" formaction="{{ mail.toggle_important_url }}" formmethod="post" class="mail-flag-btn {% if mail.is_important %}active-important{% endif %}" title="{% if mail.is_important %}取消重要{% else %}设为重要{% endif %}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M7 2h10v7l-5 3-5-3V2z"></path><path d="M7 9v13l5-3 5 3V9"></path></svg></button>'
important_replace = '<button type="submit" form="delete-selected-form" formaction="{{ mail.toggle_important_url }}" formmethod="post" class="mail-flag-btn icon-btn {% if mail.is_important %}active-important{% endif %}" data-tooltip="{% if mail.is_important %}取消重要{% else %}设为重要{% endif %}"><svg viewBox="0 0 24 24" fill="{% if mail.is_important %}#ef4444{% else %}none{% endif %}" stroke="{% if mail.is_important %}#ef4444{% else %}currentColor{% endif %}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg></button>'
if important_search in content:
    content = content.replace(important_search, important_replace)

# Let's remove the title attribute from mail-flag-btn which causes the default slow browser tooltip
content = content.replace('title="{% if mail.is_starred %}取消星标{% else %}设为星标{% endif %}"', 'data-tooltip="{% if mail.is_starred %}取消星标{% else %}设为星标{% endif %}"')
content = content.replace('title="{% if mail.is_important %}取消重要{% else %}设为重要{% endif %}"', 'data-tooltip="{% if mail.is_important %}取消重要{% else %}设为重要{% endif %}"')

with open("app/ui/page_builders.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Icons fixed successfully.")