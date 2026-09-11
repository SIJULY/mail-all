"""常量模块。

第三阶段说明：
- 本文件仅承载已明确、安全可迁移的常量
- 所有值保持与原 app.py 一致
- 不新增常量，不改变行为
- 未读取源码的部分：不迁移，不改动
"""

EMAILS_PER_PAGE = 50
EMAILS_PER_PAGE_OPTIONS = [20, 50, 100, 200]
CLEANUP_INTERVAL_DAYS = 1
EMAILS_TO_KEEP = 1000

__all__ = [
    "CLEANUP_INTERVAL_DAYS",
    "EMAILS_PER_PAGE",
    "EMAILS_PER_PAGE_OPTIONS",
    "EMAILS_TO_KEEP",
]
