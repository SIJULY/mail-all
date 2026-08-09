import re
with open("app/ui/page_builders.py", "r", encoding="utf-8") as f:
    content = f.read()

content = content.replace(
    ".compose-panel{padding:24px 24px 28px;background:#fff;}",
    ".compose-panel{padding:24px 24px 28px;background:#fff;flex:1;overflow-y:auto;min-height:0;}"
)

# Also let's check .rich-editor max height maybe?
# .rich-editor{min-height:360px;...}
# We can let it expand naturally inside the scrollable .compose-panel.

with open("app/ui/page_builders.py", "w", encoding="utf-8") as f:
    f.write(content)
