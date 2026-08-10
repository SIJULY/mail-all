import re

with open("app/ui/page_builders.py", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Update onclick
content = content.replace(
    "onclick=\"copyCode(event, '{{mail.preview_text|e}}')\"",
    "onclick=\"copyCode(event, '{{mail.preview_text|e}}', {{mail.id}})\""
)

# 2. Update function definition
search_func = """function copyCode(e, code) {
    e.preventDefault();
    e.stopPropagation();
    
    const btn = e.currentTarget;
    const originalHTML = btn.innerHTML;
    const successHTML = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="#16a34a" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    
    const showSuccess = () => {
        btn.innerHTML = successHTML;
        setTimeout(() => { btn.innerHTML = originalHTML; }, 2000);
    };"""

replace_func = """function copyCode(e, code, emailId) {
    e.preventDefault();
    e.stopPropagation();
    
    const btn = e.currentTarget;
    const originalHTML = btn.innerHTML;
    const successHTML = '<svg viewBox="0 0 24 24" width="14" height="14" stroke="#16a34a" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
    
    const markAsRead = () => {
        if (emailId) {
            fetch('/api/mark_read/' + emailId, { method: 'POST' })
                .then(res => res.json())
                .then(data => {
                    if (data.status === 'success') {
                        const tr = btn.closest('tr');
                        if (tr && tr.classList.contains('unread')) {
                            tr.classList.remove('unread');
                            tr.classList.add('read');
                            const unreadDot = tr.querySelector('.unread-dot');
                            if (unreadDot) unreadDot.remove();
                            const unreadBadge = tr.querySelector('.unread-badge');
                            if (unreadBadge) unreadBadge.remove();
                            const subj = tr.querySelector('.mail-subject.unread');
                            if (subj) subj.classList.remove('unread');
                            const from = tr.querySelector('.mail-from.unread');
                            if (from) from.classList.remove('unread');
                            
                            if (typeof autoRefreshInbox === 'function') {
                                setTimeout(autoRefreshInbox, 500);
                            }
                        }
                    }
                }).catch(err => console.error('Failed to mark read', err));
        }
    };

    const showSuccess = () => {
        btn.innerHTML = successHTML;
        setTimeout(() => { btn.innerHTML = originalHTML; }, 2000);
        markAsRead();
    };"""

content = content.replace(search_func, replace_func)

with open("app/ui/page_builders.py", "w", encoding="utf-8") as f:
    f.write(content)

print("copyCode function updated.")