"""反垃圾邮件过滤服务模块。"""

import re
import logging
from typing import Dict, List, Optional

from app.repositories.db import get_db_conn

logger = logging.getLogger(__name__)

# 支持的规则类型
RULE_TYPES = {
    "sender_email": "发件人邮箱",
    "sender_domain": "发件人域名",
    "subject_keyword": "主题关键词",
    "subject_regex": "主题正则",
}


def get_all_spam_rules() -> List[Dict]:
    """获取所有反垃圾邮件规则。"""
    conn = get_db_conn()
    try:
        rows = conn.execute(
            "SELECT id, rule_type, rule_value, created_at FROM spam_filter_rules ORDER BY id DESC"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def add_spam_rule(rule_type: str, rule_value: str) -> Optional[int]:
    """添加一条反垃圾邮件规则，返回新规则 ID。"""
    if rule_type not in RULE_TYPES:
        raise ValueError(f"不支持的规则类型: {rule_type}")
    rule_value = rule_value.strip()
    if not rule_value:
        raise ValueError("规则值不能为空")

    # 对正则类型做语法校验
    if rule_type == "subject_regex":
        try:
            re.compile(rule_value)
        except re.error as e:
            raise ValueError(f"正则表达式语法错误: {e}")

    conn = get_db_conn()
    try:
        # 去重检查
        existing = conn.execute(
            "SELECT id FROM spam_filter_rules WHERE rule_type = ? AND rule_value = ?",
            (rule_type, rule_value),
        ).fetchone()
        if existing:
            raise ValueError("该规则已存在")

        cursor = conn.execute(
            "INSERT INTO spam_filter_rules (rule_type, rule_value) VALUES (?, ?)",
            (rule_type, rule_value),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def delete_spam_rule(rule_id: int) -> bool:
    """删除一条反垃圾邮件规则，返回是否成功。"""
    conn = get_db_conn()
    try:
        result = conn.execute(
            "DELETE FROM spam_filter_rules WHERE id = ?", (rule_id,)
        )
        conn.commit()
        return result.rowcount > 0
    finally:
        conn.close()


def is_spam(sender: str, subject: str) -> bool:
    """检查邮件是否命中反垃圾邮件规则。"""
    rules = get_all_spam_rules()
    if not rules:
        return False

    sender = (sender or "").strip().lower()
    subject = (subject or "").strip()
    subject_lower = subject.lower()

    # 从发件人中提取邮箱地址和域名
    sender_email = ""
    sender_domain = ""
    if "<" in sender and ">" in sender:
        # 格式: "Name <email@domain.com>"
        match = re.search(r"<([^>]+)>", sender)
        if match:
            sender_email = match.group(1).lower()
    elif "@" in sender:
        sender_email = sender.lower()

    if sender_email and "@" in sender_email:
        sender_domain = sender_email.split("@", 1)[1]

    for rule in rules:
        rule_type = rule["rule_type"]
        rule_value = (rule["rule_value"] or "").strip()
        if not rule_value:
            continue

        try:
            if rule_type == "sender_email":
                # 精确匹配发件人邮箱（忽略大小写）
                if sender_email == rule_value.lower():
                    logger.info(f"反垃圾: 命中发件人邮箱规则 [{rule_value}], sender={sender}")
                    return True
                # 也检查完整 sender 字段中是否包含该邮箱
                if rule_value.lower() in sender:
                    logger.info(f"反垃圾: 命中发件人邮箱规则 [{rule_value}], sender={sender}")
                    return True

            elif rule_type == "sender_domain":
                # 匹配发件人域名（忽略大小写）
                rv = rule_value.lower().lstrip("@")
                if sender_domain == rv or sender_domain.endswith("." + rv):
                    logger.info(f"反垃圾: 命中发件人域名规则 [{rule_value}], sender={sender}")
                    return True

            elif rule_type == "subject_keyword":
                # 主题包含关键词（忽略大小写）
                if rule_value.lower() in subject_lower:
                    logger.info(f"反垃圾: 命中主题关键词规则 [{rule_value}], subject={subject}")
                    return True

            elif rule_type == "subject_regex":
                # 主题匹配正则表达式
                if re.search(rule_value, subject, re.IGNORECASE):
                    logger.info(f"反垃圾: 命中主题正则规则 [{rule_value}], subject={subject}")
                    return True

        except Exception as e:
            logger.warning(f"反垃圾规则执行异常: rule_id={rule['id']}, type={rule_type}, error={e}")
            continue

    return False


__all__ = ["get_all_spam_rules", "add_spam_rule", "delete_spam_rule", "is_spam", "RULE_TYPES"]
