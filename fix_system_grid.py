import re

with open('app/ui/page_builders.py', 'r', encoding='utf-8') as f:
    content = f.read()

lines = content.split('\n')
for i, line in enumerate(lines):
    if "{% elif nav_mode == 'system' %}" in line:
        line = line.replace('<div class="detail-body" style="padding:24px; background:#f8fbff; min-height:80vh;">',
            '<div class="detail-body" style="padding:24px; background:#f8fbff; min-height:80vh; display:grid; grid-template-columns:repeat(auto-fill, minmax(420px, 1fr)); gap:24px; align-items:stretch;">')
        line = line.replace('class="domain-form-card" style="margin-bottom: 24px;"', 'class="domain-form-card" style="margin: 0; box-sizing: border-box; display: flex; flex-direction: column;"')
        lines[i] = line
        break

with open('app/ui/page_builders.py', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
    
print("Update applied")
