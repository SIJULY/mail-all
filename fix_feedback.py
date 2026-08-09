import re

with open("app/ui/page_builders.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update CSS for selectable tooltip
tooltip_css_old = """.help-tooltip { position: relative; cursor: help; color: #94a3b8; display: inline-flex; }
.help-tooltip::before {
    content: '';
    position: absolute;
    top: 100%; left: -20px; right: -20px; height: 20px;
    z-index: 999;
    display: none;
}
.help-tooltip:hover::before { display: block; }
.help-tooltip::after {
    content: attr(data-tooltip);
    position: absolute;
    top: 100%; right: 0;
    margin-top: 8px;
    background: rgba(15, 23, 42, 0.95);
    color: #fff;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 13px;
    line-height: 1.6;
    white-space: pre-wrap;
    width: max-content;
    max-width: 320px;
    z-index: 1000;
    pointer-events: auto;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
    opacity: 0;
    visibility: hidden;
    transition: opacity 0.2s 0.1s, visibility 0.2s 0.1s;
}
.help-tooltip:hover::after, .help-tooltip:focus-within::after {
    opacity: 1;
    visibility: visible;
    transition-delay: 0s;
}"""

tooltip_css_new = """.help-tooltip { position: relative; cursor: help; color: #94a3b8; display: inline-flex; }
.tooltip-content {
    position: absolute;
    top: 100%; right: 0;
    margin-top: 8px;
    background: rgba(15, 23, 42, 0.95);
    color: #fff;
    padding: 10px 14px;
    border-radius: 8px;
    font-size: 13px;
    line-height: 1.6;
    white-space: pre-wrap;
    width: max-content;
    max-width: 320px;
    z-index: 1000;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
    opacity: 0;
    visibility: hidden;
    transition: opacity 0.2s 0.1s, visibility 0.2s 0.1s;
    user-select: text; /* allow text selection */
}
.tooltip-content::before {
    content: '';
    position: absolute;
    bottom: 100%; left: -20px; right: -20px; height: 20px;
}
.help-tooltip:hover .tooltip-content, .help-tooltip:focus-within .tooltip-content {
    opacity: 1;
    visibility: visible;
    transition-delay: 0s;
}"""

content = content.replace(tooltip_css_old, tooltip_css_new)

# 2. Update HTML for tooltip 1 (发信设置)
# Also remove the "发信模式" block from the HTML.
# And fix the buttons flex layout to space-between
card1_old = """<div class="domain-form-card" style="margin: 0; box-sizing: border-box; display: flex; flex-direction: column; height: 100%;"><div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;"><div style="font-size: 16px; font-weight: 800; color: #1e293b;">发信设置</div><div class="help-tooltip" data-tooltip="说明：这里可以配置发信所需的 Resend API，保存后立即生效。&#10;当配置完整后，左侧 撰写邮件 按钮会自动点亮。&#10;Resend API 获取：注册 resend.com 后生成 API Key 填入即可。"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg></div></div>{% if sending_enabled %}<div class="smtp-status ok">当前状态：发件功能已启用</div>{% else %}<div class="smtp-status off">当前状态：发件功能未配置完整</div>{% endif %}<form method="post" action="{{ url_for('manage_smtp_settings') }}" class="smtp-form" style="display: flex; flex-direction: column; flex: 1;"><input type="hidden" name="send_mode" value="resend"><div class="smtp-field full"><label style="font-size:15px;color:#1e40af;border-bottom:1px solid #bfdbfe;padding-bottom:8px;margin-bottom:12px;">发信模式</label><div class="editor-switch"><label class="editor-chip" style="background:var(--primary-soft);color:var(--primary-2);border-color:#ddd6fe;cursor:default;"><input type="radio" name="send_mode_display" value="resend" checked disabled>Resend API 模式</label></div></div><div id="resend-config-wrap" style="display:block;grid-column:1 / -1;"><div class="smtp-field full"><label>Resend Token</label><input type="password" name="resend_token" value="" placeholder="留空表示不修改已保存 Token"><small>{% if smtp_modal_data.resend_token %}当前状态：已保存 Resend Token。若不想修改，可留空。{% else %}当前状态：尚未配置 Resend Token，请填写后保存。{% endif %}</small></div></div><div class="smtp-field full" style="margin-top:12px;"><label>默认发件邮箱</label><input type="email" name="default_sender" value="{{ smtp_modal_data.default_sender }}" placeholder="例如 no-reply@example.com" required></div><div class="smtp-field full" style="display:flex;justify-content:flex-end;align-items:center;margin-top:auto;padding-top:16px;width:100%;gap:12px;"><button type="button" class="btn btn-success" onclick="document.getElementById('test-smtp-form').submit();">发送测试邮件</button><button type="submit" class="btn btn-primary">保存设置</button></div></form><form id="test-smtp-form" method="post" action="{{ url_for('send_test_smtp_email') }}" style="display:none;"></form></div>"""

card1_new = """<div class="domain-form-card" style="margin: 0; box-sizing: border-box; display: flex; flex-direction: column; height: 100%;"><div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;"><div style="font-size: 16px; font-weight: 800; color: #1e293b;">发信设置</div><div class="help-tooltip"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg><div class="tooltip-content">说明：这里可以配置发信所需的 Resend API，保存后立即生效。&#10;当配置完整后，左侧 撰写邮件 按钮会自动点亮。&#10;Resend API 获取：注册 resend.com 后生成 API Key 填入即可。</div></div></div>{% if sending_enabled %}<div class="smtp-status ok">当前状态：发件功能已启用</div>{% else %}<div class="smtp-status off">当前状态：发件功能未配置完整</div>{% endif %}<form method="post" action="{{ url_for('manage_smtp_settings') }}" class="smtp-form" style="display: flex; flex-direction: column; flex: 1;"><input type="hidden" name="send_mode" value="resend"><div id="resend-config-wrap" style="display:block;grid-column:1 / -1;"><div class="smtp-field full"><label>Resend Token</label><input type="password" name="resend_token" value="" placeholder="留空表示不修改已保存 Token"><small>{% if smtp_modal_data.resend_token %}当前状态：已保存 Resend Token。若不想修改，可留空。{% else %}当前状态：尚未配置 Resend Token，请填写后保存。{% endif %}</small></div></div><div class="smtp-field full" style="margin-top:12px;"><label>默认发件邮箱</label><input type="email" name="default_sender" value="{{ smtp_modal_data.default_sender }}" placeholder="例如 no-reply@example.com" required></div><div class="smtp-field full" style="display:flex;justify-content:space-between;align-items:center;margin-top:auto;padding-top:16px;width:100%;"><button type="button" class="btn btn-success" onclick="document.getElementById('test-smtp-form').submit();">发送测试邮件</button><button type="submit" class="btn btn-primary">保存设置</button></div></form><form id="test-smtp-form" method="post" action="{{ url_for('send_test_smtp_email') }}" style="display:none;"></form></div>"""
content = content.replace(card1_old, card1_new)

# 3. Update HTML for tooltip 2 (邮件推送) and buttons layout to space-between
card3_old = """<div class="domain-form-card" style="margin: 0; box-sizing: border-box; display: flex; flex-direction: column; height: 100%;"><div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;"><div style="font-size: 16px; font-weight: 800; color: #1e293b;">邮件推送</div><div class="help-tooltip" data-tooltip="对接 Telegram 机器人后，收到新邮件会自动发送通知给指定的 Chat ID。&#10;如何获取机器人Token？在 Telegram 中搜索 @BotFather，发送 /newbot 创建机器人并获取 Token。&#10;Chat ID 可以通过向机器人发送任意消息后，访问 https://api.telegram.org/bot[Token]/getUpdates 获取。"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg></div></div><form method="post" action="{{ url_for('manage_system_settings') }}" class="smtp-form" style="display: flex; flex-direction: column; flex: 1;"><input type="hidden" name="action" value="tg"><div class="smtp-field full" style="display: flex; align-items: center; justify-content: space-between; flex-direction: row; margin-top: 0; padding: 12px 0; border-bottom: 1px solid var(--line-soft);"><label style="margin-bottom: 0;">Telegram 机器人</label><label style="display:flex;align-items:center;gap:6px;font-size:14px;font-weight:800;color:#1d4ed8; margin: 0;"><input type="checkbox" name="tg_enabled" value="on" {% if system_modal_data.tg_enabled %}checked{% endif %}> 启用</label></div><div class="smtp-field full" style="margin-top: 16px;"><label>Bot Token</label><input type="password" name="tg_bot_token" value="" placeholder="留空表示不修改当前保存的 Token"><small>{% if system_modal_data.tg_bot_token %}当前状态：已保存 Bot Token ({{ system_modal_data.tg_bot_token_display }})。{% else %}当前状态：尚未配置 Telegram Bot Token。{% endif %}</small></div><div class="smtp-field full" style="margin-top:12px;"><label>Chat ID</label><input type="text" name="tg_chat_id" value="{{ system_modal_data.tg_chat_id }}" placeholder="例如 5328312780"></div><div class="smtp-field full" style="margin-top:12px;"><label>发件人显示方式</label><select name="tg_sender_format" style="width:100%;padding:13px 14px;border:1px solid #d1d5db;border-radius:14px;font-size:14px;outline:none;font-weight:600;background:#fff;"><option value="name" {% if system_modal_data.tg_sender_format == 'name' %}selected{% endif %}>仅名字</option><option value="email" {% if system_modal_data.tg_sender_format == 'email' %}selected{% endif %}>仅邮箱</option><option value="full" {% if system_modal_data.tg_sender_format == 'full' %}selected{% endif %}>名字 + 邮箱</option></select></div><div class="smtp-field full" style="margin-top:12px;"><label>收件人显示</label><select name="tg_recipient_display" style="width:100%;padding:13px 14px;border:1px solid #d1d5db;border-radius:14px;font-size:14px;outline:none;font-weight:600;background:#fff;"><option value="show" {% if system_modal_data.tg_recipient_display == 'show' %}selected{% endif %}>显示</option><option value="hide" {% if system_modal_data.tg_recipient_display == 'hide' %}selected{% endif %}>隐藏</option></select></div><div class="smtp-field full" style="display:flex;justify-content:flex-end;align-items:center;margin-top:auto;padding-top:16px;width:100%;gap:12px;"><button type="button" class="btn btn-success" onclick="document.getElementById('test-tg-form').submit();">发送测试通知</button><button type="submit" class="btn btn-primary">保存设置</button></div></form><form id="test-tg-form" method="post" action="{{ url_for('send_test_tg_message') }}" style="display:none;"></form></div>"""

card3_new = """<div class="domain-form-card" style="margin: 0; box-sizing: border-box; display: flex; flex-direction: column; height: 100%;"><div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;"><div style="font-size: 16px; font-weight: 800; color: #1e293b;">邮件推送</div><div class="help-tooltip"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg><div class="tooltip-content">对接 Telegram 机器人后，收到新邮件会自动发送通知给指定的 Chat ID。&#10;如何获取机器人Token？在 Telegram 中搜索 @BotFather，发送 /newbot 创建机器人并获取 Token。&#10;Chat ID 可以通过向机器人发送任意消息后，访问 https://api.telegram.org/bot[Token]/getUpdates 获取。</div></div></div><form method="post" action="{{ url_for('manage_system_settings') }}" class="smtp-form" style="display: flex; flex-direction: column; flex: 1;"><input type="hidden" name="action" value="tg"><div class="smtp-field full" style="display: flex; align-items: center; justify-content: space-between; flex-direction: row; margin-top: 0; padding: 12px 0; border-bottom: 1px solid var(--line-soft);"><label style="margin-bottom: 0;">Telegram 机器人</label><label style="display:flex;align-items:center;gap:6px;font-size:14px;font-weight:800;color:#1d4ed8; margin: 0;"><input type="checkbox" name="tg_enabled" value="on" {% if system_modal_data.tg_enabled %}checked{% endif %}> 启用</label></div><div class="smtp-field full" style="margin-top: 16px;"><label>Bot Token</label><input type="password" name="tg_bot_token" value="" placeholder="留空表示不修改当前保存的 Token"><small>{% if system_modal_data.tg_bot_token %}当前状态：已保存 Bot Token ({{ system_modal_data.tg_bot_token_display }})。{% else %}当前状态：尚未配置 Telegram Bot Token。{% endif %}</small></div><div class="smtp-field full" style="margin-top:12px;"><label>Chat ID</label><input type="text" name="tg_chat_id" value="{{ system_modal_data.tg_chat_id }}" placeholder="例如 5328312780"></div><div class="smtp-field full" style="margin-top:12px;"><label>发件人显示方式</label><select name="tg_sender_format" style="width:100%;padding:13px 14px;border:1px solid #d1d5db;border-radius:14px;font-size:14px;outline:none;font-weight:600;background:#fff;"><option value="name" {% if system_modal_data.tg_sender_format == 'name' %}selected{% endif %}>仅名字</option><option value="email" {% if system_modal_data.tg_sender_format == 'email' %}selected{% endif %}>仅邮箱</option><option value="full" {% if system_modal_data.tg_sender_format == 'full' %}selected{% endif %}>名字 + 邮箱</option></select></div><div class="smtp-field full" style="margin-top:12px;"><label>收件人显示</label><select name="tg_recipient_display" style="width:100%;padding:13px 14px;border:1px solid #d1d5db;border-radius:14px;font-size:14px;outline:none;font-weight:600;background:#fff;"><option value="show" {% if system_modal_data.tg_recipient_display == 'show' %}selected{% endif %}>显示</option><option value="hide" {% if system_modal_data.tg_recipient_display == 'hide' %}selected{% endif %}>隐藏</option></select></div><div class="smtp-field full" style="display:flex;justify-content:space-between;align-items:center;margin-top:auto;padding-top:16px;width:100%;"><button type="button" class="btn btn-success" onclick="document.getElementById('test-tg-form').submit();">发送测试通知</button><button type="submit" class="btn btn-primary">保存设置</button></div></form><form id="test-tg-form" method="post" action="{{ url_for('send_test_tg_message') }}" style="display:none;"></form></div>"""
content = content.replace(card3_old, card3_new)

with open("app/ui/page_builders.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Updated app/ui/page_builders.py successfully.")