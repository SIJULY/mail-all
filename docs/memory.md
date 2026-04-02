# 重构记忆文件

## 当前目标
在不改变现有行为的前提下，将大型单文件 `app.py` 逐步拆分为多文件项目结构。

## 不可违反的重构约束
1. 所有现有功能必须保持不变
2. 不能丢失任何功能
3. 不能新增任何功能
4. UI 必须完全保持不变
5. 路由、参数名、表单字段、返回行为尽量保持不变
6. SMTP 行为保持不变
7. 所有代码都必须从现有源码中迁移、拆分、归类
8. 不要凭空发明实现，不要擅自优化业务逻辑
9. 如果某段源码还没读取到，必须标记：未读取，不迁移，不改动
10. 重构必须采用分阶段、可回滚、可验证的方式进行
11. 优先做结构拆分，暂不做业务优化
12. 每一轮都必须明确：本轮已完成、下一步计划、风险与待确认项

## 当前已知事实
- 项目当前为 Flask 单文件应用
- 存在根级 `app.py`
- 已生成静态扫描结果：`app_scan.json`
- 已知扫描摘要：
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

## 已完成步骤
1. 明确重构硬性约束与工作方式
2. 完成静态扫描
3. 确定第一阶段只做结构搭建与记录机制
4. 设计目录结构
5. 列出第一阶段文件清单
6. 创建目录结构与占位文件
7. 写入计划、日志、记忆文件模板
8. 完成第二阶段前置盘点与映射
9. 第三阶段已迁移明确、安全的配置项到 `app/config.py`
10. 第三阶段已迁移明确、安全的常量到 `app/constants.py`
11. `app.py` 已做最小必要修改，改为从新模块导入配置/常量
12. `app` 对象、`handler`、`SECRET_KEY` 保持在 `app.py`
13. 本阶段未迁移业务函数，未修改路由、UI、SMTP 实现
14. 已创建辅助提取脚本并提取低风险函数完整函数体
15. 已迁移第一批低风险基础函数到 `app/repositories/*` 与 `app/services/*`
16. `app.py` 已改为导入 `get_db_conn`、`init_db`、`get_app_setting`、`set_app_setting`、`get_smtp_config`、`is_smtp_configured`
17. `init_db()` 调用位置保持不变
18. 已清理错误嵌套路径产物，仅保留项目根目录下辅助脚本与提取结果
19. 已迁移装饰器到 `app/utils/decorators.py`
20. 已迁移 `parse_request_timestamp` 到 `app/utils/time_utils.py`
21. 已迁移 `get_valid_per_page` 到 `app/utils/response.py`
22. `app.py` 已改为导入上述函数并移除原定义
23. 已迁移纯查询/低风险数据函数到 `app/repositories/mail_repo.py`
24. 已迁移：`get_managed_mailbox_by_id`、`get_managed_domains`、`get_primary_domain`、`delete_managed_domain`、`set_primary_domain`
26. 已迁移域名管理相关函数到 `app/repositories/mail_repo.py`
27. 已迁移可独立安全迁移的纯函数/消息处理函数到 `app/utils/mail_utils.py` 与 `app/utils/time_utils.py`
28. 已迁移：`extract_code_from_body`、`strip_tags_for_preview`、`normalize_email_address`、`normalize_domain`、`row_timestamp_to_utc`
29. 已迁移消息序列化函数到 `app/services/message_service.py`
30. 已迁移：`serialize_moemail_message`
31. `app.py` 已改为导入上述函数并移除原定义
33. 已迁移：`generate_local_part`、`add_managed_domain`、`toggle_domain_active`、`choose_moemail_domain`
34. `app.py` 已改为导入上述函数并移除原定义
35. 已修复 `app.py` 旧代码区未闭合三引号，恢复整体语法可编译状态
36. 已迁移中低风险辅助函数到 `app/services/cleanup_service.py`、`app/services/message_service.py`、`app/services/view_service.py`、`app/repositories/mail_repo.py`
37. 已迁移：`run_cleanup_if_needed`、`decode_mime_header_value`、`extract_body_from_message`、`process_email_data`、`ensure_managed_mailbox`、`build_page_url`、`can_delete_email`、`build_mail_query_context`、`get_email_detail_for_inline`
38. `app.py` 已清理对应可安全移除的重复定义，当前主要剩余路由/UI/登录/SMTP/启动等高风险区域

## 下一步计划
1. 继续仅围绕高风险区域做更细颗粒度映射与边界确认
2. 暂不直接迁移高风险路由、UI、SMTP 发信/收件、启动入口
3. 未读取源码部分继续保持：不迁移，不改动

## 当前未确认项
1. 全部业务函数的完整归类
2. 全部路由的逐条映射
3. UI 的完整生成方式（虽已确认存在 `render_template_string`，但未完整读全）
4. 所有表单字段与请求参数使用点
5. SMTP 发信/收件完整实现细节
6. 启动入口完整依赖链的所有上下文
7. `process_email_data(...)`、`base_view_logic(...)` 等高风险函数仍未完整读取
8. 未读取的源码部分一律不迁移、不改动
