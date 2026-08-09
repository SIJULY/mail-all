import re

with open('app/ui/page_builders.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. CSS adjustments for scrollbar
content = content.replace(
    '*{box-sizing:border-box;} html,body{height:100%;}',
    '*{box-sizing:border-box;} html,body{height:100%;overflow:hidden;}'
)
content = content.replace(
    '.app-shell{min-height:100vh;}',
    '.app-shell{height:100vh;display:flex;overflow:hidden;}'
)
content = content.replace(
    '.main{margin-left:276px;min-height:100vh;display:flex;flex-direction:column;min-width:0;}',
    '.main{margin-left:276px;height:100vh;overflow-y:auto;display:flex;flex-direction:column;min-width:0;flex:1;}'
)
content = content.replace(
    '.content{padding:22px;}',
    '.content{padding:22px;flex:1;display:flex;flex-direction:column;min-height:0;}'
)
content = content.replace(
    '.detail-page,.compose-page{background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:24px;box-shadow:var(--shadow);overflow:hidden;}',
    '.detail-page,.compose-page{background:rgba(255,255,255,.96);border:1px solid var(--line);border-radius:24px;box-shadow:var(--shadow);overflow:hidden;display:flex;flex-direction:column;flex:1;min-height:0;}'
)
content = content.replace(
    '.detail-body{background:#fff;min-height:620px;}',
    '.detail-body{background:#fff;display:flex;flex-direction:column;flex:1;min-height:0;overflow:hidden;}'
)

# 2. Add tooltip CSS
tooltip_css = '.icon-btn{position:relative;} .icon-btn[data-tooltip]:hover::after{content:attr(data-tooltip);position:absolute;bottom:100%;left:50%;transform:translateX(-50%) translateY(-6px);background:rgba(15,23,42,.9);color:#fff;padding:5px 8px;border-radius:6px;font-size:12px;white-space:nowrap;z-index:1000;pointer-events:none;opacity:1;}'

# Append it to the end of the <style> block
content = content.replace(
    '</style>',
    tooltip_css + '\n</style>'
)

# 3. Modify iframe and text body
content = content.replace(
    '<iframe srcdoc="{{ selected_email.iframe_srcdoc|e }}" style="width:100%;height:100%;min-height:calc(100vh - 250px);border:none;"></iframe>',
    '<iframe srcdoc="{{ selected_email.iframe_srcdoc|e }}" style="width:100%;height:100%;border:none;flex:1;"></iframe>'
)
content = content.replace(
    '<div style="white-space:pre-wrap;word-wrap:break-word;line-height:1.7;">{{ selected_email.text_body_html|safe }}</div>',
    '<div style="white-space:pre-wrap;word-wrap:break-word;line-height:1.7;overflow-y:auto;flex:1;padding:22px;">{{ selected_email.text_body_html|safe }}</div>'
)

# 4. Replace title= with data-tooltip= for icon-btn
content = re.sub(r'class="icon-btn([^"]*)" title="', r'class="icon-btn\1" data-tooltip="', content)

with open('app/ui/page_builders.py', 'w', encoding='utf-8') as f:
    f.write(content)