with open("app/routes/ui_routes.py", "r", encoding="utf-8") as f:
    content = f.read()

new_endpoint = """
    @app.route("/api/mark_read/<int:email_id>", methods=["POST"])
    def mark_email_read(email_id):
        conn = get_db_conn()
        try:
            conn.execute("UPDATE received_emails SET is_read = 1 WHERE id = ?", (email_id,))
            conn.commit()
            return jsonify({"status": "success"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
        finally:
            conn.close()

"""

if "/api/mark_read" not in content:
    # insert before @app.route("/api/unread_count")
    content = content.replace('    @app.route("/api/unread_count")', new_endpoint + '    @app.route("/api/unread_count")')
    with open("app/routes/ui_routes.py", "w", encoding="utf-8") as f:
        f.write(content)
    print("Added /api/mark_read endpoint.")
else:
    print("Endpoint already exists.")
