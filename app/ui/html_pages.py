"""HTML 页面模板模块。"""

LOGIN_PAGE_TEMPLATE = '''
<!DOCTYPE html><html><head><title>登录 - {{ SYSTEM_TITLE }}</title><style>
body{display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;margin:0;background:linear-gradient(135deg,#eef4ff 0%,#f8fafc 100%);}
.main-title{font-size:2em;color:#1f2937;margin-bottom:1em;font-weight:bold;}
.login-box{padding:2em;border:1px solid #e5e7eb;border-radius:16px;background-color:#fff;box-shadow:0 10px 30px rgba(15,23,42,0.08);width:320px;}
h2 {text-align:center;color:#111827;margin-top:0;margin-bottom:1.5em;}
form {display:flex;flex-direction:column;}
label {margin-bottom:0.5em;color:#555;}
input[type="text"], input[type="password"] {padding:0.9em;margin-bottom:1em;border:1px solid #d1d5db;border-radius:10px;font-size:1em;}
input[type="submit"] {padding:0.9em;border:none;border-radius:10px;background:linear-gradient(135deg,#2563eb,#3b82f6);color:white;cursor:pointer;font-size:1em;transition:all 0.2s;}
input[type="submit"]:hover {transform:translateY(-1px);}
.error{color:red;text-align:center;margin-bottom:1em;}
{% with m=get_flashed_messages(with_categories=true) %}{% for c,msg in m %}<p class="error">{{msg}}</p>{% endfor %}{% endwith %}
</style></head><body>
<h1 class="main-title">{{ SYSTEM_TITLE }}</h1>
<div class="login-box"><h2>邮箱登录</h2>
<form method="post">
<label for="email">邮箱地址 (或管理员账户):</label><input type="text" name="email" required>
<label for="password">密码:</label><input type="password" name="password" required>
<input type="submit" value="登录"></form></div></body></html>
'''
