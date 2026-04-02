# 重构日志

## 记录规则
1. 只记录已经实际完成的动作
2. 每一步都必须可验证、可回滚
3. 不记录猜测性迁移
4. 未读取源码的部分必须注明：未读取，不迁移，不改动
5. 每次操作后都要写明验证方式和结果

---

## [阶段 0] 重构前盘点
### 已完成
- 已生成静态扫描文件：`app_scan.json`
- 已确认当前项目为单文件 Flask 应用
- 已确认当前阶段不直接迁移业务逻辑

### 扫描摘要
- imports_count = 27
- top_level_function_count = 80
- top_level_class_count = 1
- route_count = 32
- route_function_count = 32
- global_variable_count = 25
- smtp_related_function_or_class_count = 8
- startup_entry_count = 1
- app_creation_count = 1
- blueprint_creation_count = 0

### 本阶段结论
- 先建立项目框架和记录机制
- 暂不迁移业务实现
- 暂不改动 UI、路由、表单字段、SMTP 行为

### 验证方式
- 检查 `app_scan.json` 是否存在
- 检查扫描摘要是否可读取

### 验证结果
- 已确认 `app_scan.json` 存在并可读取扫描摘要

### 回滚点
- 当前尚未改动业务代码，无需回滚

---

## [阶段 1] 项目框架建立
### 目标
- 创建 `app/` 多目录结构
- 创建占位文件
- 创建计划/日志/记忆文件
- 不迁移业务代码
- 不修改 `app.py`

### 实际完成
- 已创建 `app/` 目录结构
- 已创建 `routes`、`services`、`repositories`、`ui`、`utils` 子目录
- 已创建各模块 Python 占位文件
- 已创建 `docs/refactor-plan.md`
- 已创建 `docs/refactor-log.md`
- 已创建 `docs/memory.md`
- 已写入最小注释/记录内容

### 本阶段未做
- 未迁移任何业务函数
- 未修改任何 UI
- 未修改任何路由
- 未修改任何参数名、表单字段、返回行为
- 未修改 SMTP 逻辑
- 未读取源码的部分：不迁移，不改动

### 验证方式
- 检查目录和文件是否创建完成
- 检查 `app.py` 是否未改动

### 验证结果
- 目录与文件已创建完成
- 本轮未对 `app.py` 执行任何修改

### 回滚方式
- 删除新建目录与占位文件
- 保留原始单文件项目状态

---

## [阶段 3] 配置与常量迁移
### 目标
- 仅迁移已明确、安全可迁移的配置项和常量
- 写入 `app/config.py` 与 `app/constants.py`
- 对 `app.py` 做最小必要修改，保持原有行为不变
- 不迁移任何业务函数
- 不修改任何路由、UI、SMTP 实现

### 实际完成
- 已将配置项写入 `app/config.py`
- 已将常量写入 `app/constants.py`
- 已在 `app.py` 中新增从 `app.config` / `app.constants` 的导入
- 已删除 `app.py` 中对应的重复配置/常量定义
- 保留了 `app` 对象、`handler`、`SECRET_KEY` 配置在 `app.py`

### 本阶段迁移的配置项
- `DB_FILE`
- `LAST_CLEANUP_FILE`
- `ADMIN_USERNAME`
- `ADMIN_PASSWORD_HASH`
- `SYSTEM_TITLE`
- `SPECIAL_VIEW_TOKEN`
- `SERVER_PUBLIC_IP`
- `MOEMAIL_API_KEY`
- `MOEMAIL_API_KEY_HEADER`
- `MOEMAIL_DEFAULT_EXPIRY`
- `MOEMAIL_DEFAULT_ROLE`
- `SMTP_SERVER`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `DEFAULT_SENDER`

### 本阶段迁移的常量
- `EMAILS_PER_PAGE`
- `EMAILS_PER_PAGE_OPTIONS`
- `CLEANUP_INTERVAL_DAYS`
- `EMAILS_TO_KEEP`

### 本阶段未做
- 未迁移任何业务函数
- 未修改任何路由实现
- 未修改任何 SMTP 发信/收件实现
- 未修改任何 `render_template_string` 或页面 HTML
- 未移动 `app` 对象
- 未移动 `handler`
- 未移动 `app.config["SECRET_KEY"]`
- 未读取源码的部分：不迁移，不改动

### 验证方式
- 检查 `app/config.py` 与 `app/constants.py` 是否写入完成
- 检查 `app.py` 是否仅做最小必要导入替换
- 检查迁移项默认值和环境变量键名是否保持不变

### 验证结果
- `app/config.py` 与 `app/constants.py` 已写入完成
- `app.py` 已改为从新模块导入对应配置/常量
- `app`、`handler`、`SECRET_KEY` 仍保留在 `app.py`

### 回滚方式
- 将 `app/config.py` 与 `app/constants.py` 恢复为占位内容
- 将迁移出的配置/常量定义放回 `app.py`
- 移除 `app.py` 中新增的导入

---

## [阶段 4] 低风险基础函数迁移（第一批）
### 目标
- 仅迁移已完整提取并确认安全的低风险基础函数
- 不修改路由、UI、SMTP 发信/收件实现、启动入口逻辑
- 对 `app.py` 做最小必要导入替换

### 实际完成
- 已创建辅助提取脚本并提取目标函数完整函数体
- 已迁移 `get_db_conn`、`init_db` 到 `app/repositories/db.py`
- 已迁移 `get_app_setting`、`set_app_setting` 到 `app/repositories/settings_repo.py`
- 已迁移 `get_smtp_config`、`is_smtp_configured` 到 `app/services/smtp_service.py`
- 已在 `app.py` 中新增对应导入并删除原函数定义
- 已保留 `init_db()` 的原调用位置不变

### 本阶段未做
- 未迁移任何路由函数
- 未修改任何 UI 代码
- 未修改任何 SMTP 发信/收件实现
- 未修改启动入口逻辑
- 未修改 `render_template_string` 或页面 HTML
- 未读取源码的部分：不迁移，不改动

### 验证方式
- 检查提取出的函数体与迁移后的代码是否一致
- 检查 `app.py` 是否仅做导入替换和原定义移除
- 检查 `init_db()` 是否仍在原位置调用

### 验证结果
- 目标函数已完整提取并迁移
- `app.py` 已改为从新模块导入对应函数
- `init_db()` 仍在原位置调用

### 回滚方式
- 将上述函数定义放回 `app.py`
- 移除 `app.py` 中新增导入
- 将 `app/repositories/db.py`、`app/repositories/settings_repo.py`、`app/services/smtp_service.py` 恢复为占位内容

---

## [阶段 4] 低风险基础函数迁移（第二批）
### 实际完成
- 已清理错误的嵌套路径产物，仅保留项目根目录下合理辅助脚本与提取结果
- 已迁移装饰器：`moemail_api_required`、`login_required`、`admin_required`
- 已迁移纯工具函数：`parse_request_timestamp`
- 已迁移分页辅助函数：`get_valid_per_page`
- 已在 `app.py` 中新增对应导入并删除原函数定义

### 本阶段未做
- 未迁移任何路由函数
- 未修改任何 UI 代码
- 未修改任何 SMTP 发信/收件实现
- 未修改启动入口逻辑
- 未读取源码的部分：不迁移，不改动

---

## [阶段 4] 低风险基础函数迁移（第三批）
### 实际完成
- 已迁移纯查询/低风险数据函数：`get_managed_mailbox_by_id`、`get_managed_domains`、`get_primary_domain`
- 已迁移低风险更新函数：`delete_managed_domain`、`set_primary_domain`
- 已在 `app.py` 中新增对应导入并删除原函数定义

### 本阶段未做
- 未迁移任何路由函数
- 未修改任何 UI 代码
- 未修改任何 SMTP 发信/收件实现
- 未修改启动入口逻辑
- 未读取源码的部分：不迁移，不改动

---

## [阶段 4] 低风险基础函数迁移（第四批）
### 实际完成
- 已迁移域名管理相关函数到 `app/repositories/mail_repo.py`
- 已继续迁移可独立安全迁移的纯函数/消息处理函数：`extract_code_from_body`、`strip_tags_for_preview`、`normalize_email_address`、`normalize_domain`、`row_timestamp_to_utc`
- 已继续迁移消息序列化函数：`serialize_moemail_message`
- 已继续迁移剩余可独立安全迁移的低风险函数：`generate_local_part`、`add_managed_domain`、`toggle_domain_active`、`choose_moemail_domain`
- 已继续迁移中低风险辅助函数：`run_cleanup_if_needed`、`decode_mime_header_value`、`extract_body_from_message`、`process_email_data`、`ensure_managed_mailbox`、`build_page_url`、`can_delete_email`、`build_mail_query_context`、`get_email_detail_for_inline`
- 已新增模块：`app/services/cleanup_service.py`、`app/services/view_service.py`
- 已修复 `app.py` 旧代码区未闭合三引号导致的语法阻塞
- 已在 `app.py` 中新增对应导入并删除可安全移除的原函数定义，当前仅保留高风险区域函数

### 本阶段未做
- 未迁移任何路由函数
- 未修改任何 UI 代码
- 未修改任何 SMTP 发信/收件实现
- 未修改启动入口逻辑
- 未读取源码的部分：不迁移，不改动
