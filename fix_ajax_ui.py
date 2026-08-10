with open("app/ui/page_builders.py", "r", encoding="utf-8") as f:
    content = f.read()

# find script section
script_start = "<script>function copyCode(e, code) {"
new_script = """<script>
document.addEventListener('DOMContentLoaded', function() {
    const smtpForm = document.querySelector('form.smtp-form[action*="manage_smtp_settings"]');
    if (smtpForm) {
        smtpForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            const btn = this.querySelector('button[type="submit"]');
            const originalText = btn.textContent;
            btn.textContent = '保存中...';
            btn.disabled = true;

            fetch(this.action, {
                method: 'POST',
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(res => res.json())
            .then(data => {
            with open("app/ui/page_buildce    content = f.read()

# find script section
script_start = "<sce
# find script sectio } script_start = "<scr  new_script = """<script>
document.addEventListener('??document.addEventListen      const smtpForm = document.querySelector('form.smtp-fo      if (smtpForm) {
        smtpForm.addEventListener('submit', function(e) {
            e.pfi        smtpForm.a              e.preventDefault();
            const formDa              const formData = n              const btn = this.querySelector('bute,            const originalText = btn.textContent;
            btn.tac            btn.textContent = '保存中...';
  i/            btn.disabled = true;

           f
            fetch(this.action,pri                method: 'POST',
e                body: formData t                headers: {
   py")
