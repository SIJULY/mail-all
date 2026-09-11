import re

with open('app/ui/page_builders.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Remove the whole modal block
modal_block_start = content.find('</main>{% if is_admin_view and not token_view_context %}<div id="domain-modal"')
modal_block_end = content.find('{% endif %}</div><script>function copyCode')
if modal_block_start != -1 and modal_block_end != -1:
    content = content[:modal_block_start] + '</main></div><script>function copyCode' + content[modal_block_end + len('{% endif %}</div><script>function copyCode'):]

# Remove modal js functions
js_funcs_to_remove = [
    r'function openDomainModal\(\)\{[^}]+\} ',
    r'function closeDomainModal\(\)\{[^}]+\} ',
    r'function closeDomainModalByMask\(event\)\{[^}]+\} ',
    r'function openUserModal\(\)\{[^}]+\} ',
    r'function closeUserModal\(\)\{[^}]+\} ',
    r'function closeUserModalByMask\(event\)\{[^}]+\} ',
    r'function openSmtpModal\(\)\{[^}]+\} ',
    r'function closeSmtpModal\(\)\{[^}]+\} ',
    r'function closeSmtpModalByMask\(event\)\{[^}]+\} '
]
for pattern in js_funcs_to_remove:
    content = re.sub(pattern, '', content)

# Remove url param check for modals
url_check_pattern = r"const url=new URL\(window\.location\.href\);let changed=false; if\(url\.searchParams\.get\('show_domain_modal'\)==='1'\)\{openDomainModal\(\);url\.searchParams\.delete\('show_domain_modal'\);changed=true;\} if\(url\.searchParams\.get\('show_user_modal'\)==='1'\)\{openUserModal\(\);url\.searchParams\.delete\('show_user_modal'\);changed=true;\} if\(url\.searchParams\.get\('show_smtp_modal'\)==='1'\)\{openSmtpModal\(\);url\.searchParams\.delete\('show_smtp_modal'\);changed=true;\} if\(changed\)\{const newUrl=url\.pathname\+\(url\.searchParams\.toString\(\)\?'\?'\+url\.searchParams\.toString\(\):''\)\+url\.hash;window\.history\.replaceState\(\{\},'',newUrl\);\} "
content = re.sub(url_check_pattern, '', content)

with open('app/ui/page_builders.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Done!')