from app import app
from flask import session

app.testing = True
client = app.test_client()

with client.session_transaction() as sess:
    sess['user_email'] = 'sijuly@outlook.com'
    sess['is_admin'] = True

try:
    response = client.get('/compose?reply_to_id=6')
    print("Response status:", response.status_code)
    # Check if flash message is in the response text
    if "加载原始邮件以供回复时出错" in response.get_data(as_text=True):
        print("Error flash message found in response.")
except Exception as e:
    import traceback
    traceback.print_exc()

