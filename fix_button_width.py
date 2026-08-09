import re

with open('app/ui/page_builders.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace Card 1 & 3 button row
old_str1 = 'style="display:flex;justify-content:space-between;align-items:center;margin-top:auto;padding-top:16px;"'
new_str1 = 'style="display:flex;justify-content:space-between;align-items:center;margin-top:auto;padding-top:16px;width:100%;"'
content = content.replace(old_str1, new_str1)

# Replace Card 2 button row
old_str2 = 'style="display:flex;justify-content:flex-end;margin-top:auto;padding-top:16px;"'
new_str2 = 'style="display:flex;justify-content:flex-end;margin-top:auto;padding-top:16px;width:100%;"'
content = content.replace(old_str2, new_str2)

with open('app/ui/page_builders.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done. Button widths updated.")
