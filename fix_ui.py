import re

with open("app/routes/ui_routes.py", "r") as f:
    routes_content = f.read()

# Add forward_id processing logic in ui_routes.py if not already there
forward_logic = """
        forward_id = request.args.get("forward_id")
        if (
            forward_id
            and not draft_id
            and not (
                form_data.get("to")
                or form_data.get("subject")
                or form_data.get("body")
                or form_data.get("html_body")
            )
        ):
            try:
                conn = get_db_conn()
                query = "SELECT * FROM received_emails WHERE id = ? AND ifnull(is_deleted, 0) = 0"
                params = [forward_id]
                if not is_admin_view:
                    query += " AND recipient = ?"
                    params.append(session["user_email"])
                original_email = conn.execute(query, params).fetchone()
                conn.close()
                if original_email:
                    original_subject = original_email["subject"] or ""
                    form_data["subject"] = (
                        original_subject
                        if original_subject.lower().startswith("fwd:")
                        else f"Fwd: {original_subject}"
                    )
                    beijing_tz = ZoneInfo("Asia/Shanghai")
                    utc_dt = datetime.strptime(
                        original_email["timestamp"], "%Y-%m-%d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
                    bjt_str = utc_dt.astimezone(beijing_tz).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    
                    body_content = original_email["html_body"] or ""
                    if not body_content:
                        body_content = strip_tags_for_preview(original_email["body"] or "").replace("\\n", "<br>")
                    
                    forward_header = f"<br><br>---------- Forwarded message ---------<br>From: {original_email['sender']}<br>Date: {bjt_str}<br>Subject: {original_subject}<br>To: {original_email['recipient']}<br><br>"
                    
                    form_data["html_body"] = forward_header + body_content
            except Exception as e:
                pass
"""
if "forward_id = request.args.get" not in routes_content:
    routes_content = routes_content.replace('except Exception as e:\n                pass', 'except Exception as e:\n                pass\n' + forward_logic, 1)

with open("app/routes/ui_routes.py", "w") as f:
    f.write(routes_content)

with open("app/ui/page_builders.py", "r") as f:
    ui_content = f.read()

# Add forward_url to template context if not already there
if '"forward_url": url_for(' not in ui_content:
    ui_content = ui_content.replace(
        '"reply_url": url_for(\n                "compose_email",\n                reply_to_id=selected_email["id"],\n            ),',
        '"reply_url": url_for(\n                "compose_email",\n                reply_to_id=selected_email["id"],\n            ),\n            "forward_url": url_for(\n                "compose_email",\n                forward_id=selected_email["id"],\n            ),'
    )

# Fix iframe height adjustment logic (Fix 3)
ui_content = re.sub(
    r'<iframe srcdoc="\{\{ selected_email\.iframe_srcdoc\|e \}\}" style="width:100%;min-height:500px;border:none;overflow:hidden;" onload="this\.style\.height = this\.contentWindow\.document\.documentElement\.scrollHeight \+ \'px\';"></iframe>',
    '<iframe srcdoc="{{ selected_email.iframe_srcdoc|e }}" style="width:100%;height:100%;min-height:calc(100vh - 250px);border:none;"></iframe>',
    ui_content
)

# Replace action buttons with icons
old_actions_block = '{% if selected_email.can_reply %}<a href="{{ selected_email.reply_url }}" class="btn btn-primary">回复邮件</a>{% endif %}<form method="post" action="{{ selected_email.toggle_star_url }}" style="margin:0;"><button type="submit" class="btn btn-secondary">{% if selected_email.is_starred %}取消星标{% else %}设为星标{% endif %}</button></form><form method="post" action="{{ selected_email.toggle_important_url }}" style="margin:0;"><button type="submit" class="btn btn-secondary">{% if selected_email.is_important %}取消重要{% else %}设为重要{% endif %}</button></form>{% if selected_email.can_restore %}<form method="post" action="{{ selected_email.restore_url }}" style="margin:0;"><button type="submit" class="btn btn-secondary">恢复邮件</button></form>{% endif %}{% if selected_email.can_delete %}<form method="post" action="{{ selected_email.delete_url }}" style="margin:0;" onsubmit="return confirm(\'{{ selected_email.delete_confirm }}\');"><button type="submit" class="btn btn-danger">{{ selected_email.delete_label }}</button></form>{% endif %}<a href="{{ selected_back_url }}" class="detail-back">← 返回列表</a>'

new_actions_block = """{% if selected_email.can_reply %}<a href="{{ selected_email.reply_url }}" class="icon-btn" title="回复"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"/></svg></a><a href="{{ selected_email.forward_url }}" class="icon-btn" title="转发"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10H11a8 8 0 00-8 8v2M21 10l-6 6m6-6l-6-6"/></svg></a>{% endif %}<form method="post" action="{{ selected_email.toggle_star_url }}" style="margin:0;"><button type="submit" class="icon-btn" title="{% if selected_email.is_starred %}取消星标{% else %}设为星标{% endif %}"><svg viewBox="0 0 24 24" width="20" height="20" fill="{% if selected_email.is_starred %}#eab308{% else %}none{% endif %}" stroke="{% if selected_email.is_starred %}#eab308{% else %}currentColor{% endif %}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon></svg></button></form><form method="post" action="{{ selected_email.toggle_important_url }}" style="margin:0;"><button type="submit" class="icon-btn" title="{% if selected_email.is_important %}取消重要{% else %}设为重要{% endif %}"><svg viewBox="0 0 24 24" width="20" height="20" fill="{% if selected_email.is_important %}#ef4444{% else %}none{% endif %}" stroke="{% if selected_email.is_important %}#ef4444{% else %}currentColor{% endif %}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg></button></form>{% if selected_email.can_restore %}<form method="post" action="{{ selected_email.restore_url }}" style="margin:0;"><button type="submit" class="icon-btn" title="恢复邮件"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 14 4 9 9 4"></polyline><path d="M20 20v-7a4 4 0 0 0-4-4H4"></path></svg></button></form>{% endif %}{% if selected_email.can_delete %}<form method="post" action="{{ selected_email.delete_url }}" style="margin:0;" onsubmit="return confirm('{{ selected_email.delete_confirm }}');"><button type="submit" class="icon-btn text-danger" title="{{ selected_email.delete_label }}"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg></button></form>{% endif %}<a href="{{ selected_back_url }}" class="icon-btn" title="返回列表"><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg></a>"""

ui_content = ui_content.replace(old_actions_block, new_actions_block)

# Add CSS for icon-btn
css_block = ".icon-btn{background:transparent;border:none;cursor:pointer;padding:8px;border-radius:4px;color:#64748b;display:flex;align-items:center;justify-content:center;transition:background 0.2s,color 0.2s;}.icon-btn:hover{background:#f1f5f9;color:#0f172a;}.icon-btn.text-danger:hover{color:#ef4444;background:#fef2f2;}"
if ".icon-btn{" not in ui_content:
    ui_content = ui_content.replace(".btn-danger:hover{background:#dc2626;}", ".btn-danger:hover{background:#dc2626;}" + css_block)
    
# Change .detail-body layout to flex so iframe can take full height
ui_content = ui_content.replace('.detail-body{padding:24px;border-bottom-left-radius:12px;border-bottom-right-radius:12px;background:#fff;}', '.detail-body{padding:24px;border-bottom-left-radius:12px;border-bottom-right-radius:12px;background:#fff;display:flex;flex-direction:column;flex:1;}')

# Make detail-page fill height
ui_content = ui_content.replace('.detail-page{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.05);margin-bottom:24px;border:1px solid var(--line);}', '.detail-page{background:#fff;border-radius:12px;box-shadow:0 1px 3px rgba(0,0,0,0.05);margin-bottom:24px;border:1px solid var(--line);display:flex;flex-direction:column;min-height:calc(100vh - 120px);}')

with open("app/ui/page_builders.py", "w") as f:
    f.write(ui_content)
print("done")