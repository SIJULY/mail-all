import re

with open("app/ui/page_builders.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update the tooltip style
tooltip_old = """.help-tooltip { position: relative; cursor: help; color: #94a3b8; display: inline-flex; }
.help-tooltip:hover::after {
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
    pointer-events: none;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
}"""

tooltip_new = """.help-tooltip { position: relative; cursor: help; color: #94a3b8; display: inline-flex; }
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

content = content.replace(tooltip_old, tooltip_new)

# 2. Update 发信设置 card (SMTP removal + button move right)
smtp_card_old = """<div class="domain-form-card" style="margin: 0; box-sizing: border-box; display: flex; flex-direction: column; height: 100%;"><div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;"><div style="font-size: 16px; font-weight: 800; color: #1e293b;">发信设置</div><div class="help-tooltip" data-tooltip="说明：这里可以在线配置发信所需的 SMTP 中继参数，或使用 Resend API，保存后立即生效。&#10;支持 SendGrid、Postmark、SES SMTP、Mailgun、Resend 等服务。&#10;当配置完整后，左侧 撰写邮件 按钮会自动点亮。&#10;Resend API 获取：注册 resend.com 后生成 API Key 填入即可。"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg></div></div>{% if sending_enabled %}<div class="smtp-status ok">当前状态：发件功能已启用</div>{% else %}<div class="smtp-status off">当前状态：发件功能未配置完整</div>{% endif %}<form method="post" action="{{ url_for('manage_smtp_settings') }}" class="smtp-form" style="display: flex; flex-direction: column; flex: 1;"><div class="smtp-field full"><label style="font-size:15px;color:#1e40af;border-bottom:1px solid #bfdbfe;padding-bottom:8px;margin-bottom:12px;">发信模式</label><div class="editor-switch"><label class="editor-chip"><input type="radio" name="send_mode" value="smtp" {% if smtp_modal_data.send_mode != 'resend' %}checked{% endif %} onchange="document.getElementById('smtp-config-wrap').style.display='grid';document.getElementById('resend-config-wrap').style.display='none';">SMTP 模式</label><label class="editor-chip"><input type="radio" name="send_mode" value="resend" {% if smtp_modal_data.send_mode == 'resend' %}checked{% endif %} onchange="document.getElementById('smtp-config-wrap').style.display='none';document.getElementById('resend-config-wrap').style.display='block';">Resend API 模式</label></div></div><div id="smtp-config-wrap" style="display:{% if smtp_modal_data.send_mode != 'resend' %}grid{% else %}none{% endif %};grid-template-columns:1fr 1fr;gap:12px;grid-column:1 / -1;"><div class="smtp-field"><label>SMTP Server</label><input type="text" name="smtp_server" value="{{ smtp_modal_data.server }}" placeholder="例如 smtp.sendgrid.net"></div><div class="smtp-field"><label>SMTP Port</label><input type="number" name="smtp_port" value="{{ smtp_modal_data.port }}" placeholder="例如 587"></div><div class="smtp-field"><label>SMTP Username</label><input type="text" name="smtp_username" value="{{ smtp_modal_data.username }}" placeholder="例如 apikey"></div><div class="smtp-field"><label>SMTP Password</label><input type="password" name="smtp_password" value="" placeholder="留空表示不修改已保存密码"><small>{% if smtp_modal_data.password_configured %}当前状态：已保存密钥。若不想修改，可留空后直接保存。{% else %}当前状态：尚未配置密钥，请填写后保存。{% endif %}</small></div></div><div id="resend-config-wrap" style="display:{% if smtp_modal_data.send_mode == 'resend' %}block{% else %}none{% endif %};grid-column:1 / -1;"><div class="smtp-field full"><label>Resend Token</label><input type="password" name="resend_token" value="" placeholder="留空表示不修改已保存 Token"><small>{% if smtp_modal_data.resend_token %}当前状态：已保存 Resend Token。若不想修改，可留空。{% else %}当前状态：尚未配置 Resend Token，请填写后保存。{% endif %}</small></div></div><div class="smtp-field full" style="margin-top:12px;"><label>默认发件邮箱</label><input type="email" name="default_sender" value="{{ smtp_modal_data.default_sender }}" placeholder="例如 no-reply@example.com" required></div><div class="smtp-field full" style="display:flex;justify-content:space-between;align-items:center;margin-top:auto;padding-top:16px;width:100%;"><button type="button" class="btn btn-success" onclick="document.getElementById('test-smtp-form').submit();">发送测试邮件</button><button type="submit" class="btn btn-primary">保存设置</button></div></form><form id="test-smtp-form" method="post" action="{{ url_for('send_test_smtp_email') }}" style="display:none;"></form></div>"""

smtp_card_new = """<div class="domain-form-card" style="margin: 0; box-sizing: border-box; display: flex; flex-direction: column; height: 100%;"><div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;"><div style="font-size: 16px; font-weight: 800; color: #1e293b;">发信设置</div><div class="help-tooltip" data-tooltip="说明：这里可以配置发信所需的 Resend API，保存后立即生效。&#10;当配置完整后，左侧 撰写邮件 按钮会自动点亮。&#10;Resend API 获取：注册 resend.com 后生成 API Key 填入即可。"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg></div></div>{% if sending_enabled %}<div class="smtp-status ok">当前状态：发件功能已启用</div>{% else %}<div class="smtp-status off">当前状态：发件功能未配置完整</div>{% endif %}<form method="post" action="{{ url_for('manage_smtp_settings') }}" class="smtp-form" style="display: flex; flex-direction: column; flex: 1;"><input type="hidden" name="send_mode" value="resend"><div class="smtp-field full"><label style="font-size:15px;color:#1e40af;border-bottom:1px solid #bfdbfe;padding-bottom:8px;margin-bottom:12px;">发信模式</label><div class="editor-switch"><label class="editor-chip" style="background:var(--primary-soft);color:var(--primary-2);border-color:#ddd6fe;cursor:default;"><input type="radio" name="send_mode_display" value="resend" checked disabled>Resend API 模式</label></div></div><div id="resend-config-wrap" style="display:block;grid-column:1 / -1;"><div class="smtp-field full"><label>Resend Token</label><input type="password" name="resend_token" value="" placeholder="留空表示不修改已保存 Token"><small>{% if smtp_modal_data.resend_token %}当前状态：已保存 Resend Token。若不想修改，可留空。{% else %}当前状态：尚未配置 Resend Token，请填写后保存。{% endif %}</small></div></div><div class="smtp-field full" style="margin-top:12px;"><label>默认发件邮箱</label><input type="email" name="default_sender" value="{{ smtp_modal_data.default_sender }}" placeholder="例如 no-reply@example.com" required></div><div class="smtp-field full" style="display:flex;justify-content:flex-end;align-items:center;margin-top:auto;padding-top:16px;width:100%;gap:12px;"><button type="button" class="btn btn-success" onclick="document.getElementById('test-smtp-form').submit();">发送测试邮件</button><button type="submit" class="btn btn-primary">保存设置</button></div></form><form id="test-smtp-form" method="post" action="{{ url_for('send_test_smtp_email') }}" style="display:none;"></form></div>"""

content = content.replace(smtp_card_old, smtp_card_new)

# 3. Update 邮件推送 bottom button alignment to bottom-right
tg_buttons_old = """<div class="smtp-field full" style="display:flex;justify-content:space-between;align-items:center;margin-top:auto;padding-top:16px;width:100%;"><button type="button" class="btn btn-success" onclick="document.getElementById('test-tg-form').submit();">发送测试通知</button><button type="submit" class="btn btn-primary">保存设置</button></div>"""

tg_buttons_new = """<div class="smtp-field full" style="display:flex;justify-content:flex-end;align-items:center;margin-top:auto;padding-top:16px;width:100%;gap:12px;"><button type="button" class="btn btn-success" onclick="document.getElementById('test-tg-form').submit();">发送测试通知</button><button type="submit" class="btn btn-primary">保存设置</button></div>"""

content = content.replace(tg_buttons_old, tg_buttons_new)

with open("app/ui/page_builders.py", "w", encoding="utf-8") as f:
    f.write(content)

print("Updated app/ui/page_builders.py successfully.")