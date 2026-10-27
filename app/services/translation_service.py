"""邮件翻译服务：微软 Translator（Azure F0 免费档）。

手动点翻译时才调用，邮件内容只在那一刻发给微软翻译接口；不自动
翻译、不存翻译结果，页面刷新后再次点翻译会重新请求。

密钥与区域只存在服务器环境文件 mail_api.env（不进仓库、不写代码
里）：MAIL_MS_TRANSLATOR_KEY（资源页“密钥 1”）、
MAIL_MS_TRANSLATOR_REGION（资源页“位置/区域”，如 eastasia；Global
资源可留空）。没配密钥时点翻译会明确报错，不静默失败。

F0 是 Azure 定价页上的长期免费档（每月 200 万字符，非试用），不是
30 天试用；超额后当月请求会被拒绝，需升级 S1 才能继续。

HTML 邮件：只收集文本节点（标签、属性、链接、图片原样保留），按
微软多文本接口一次发一组（每组最多 50 条），按顺序一一对应贴回，
不拼分隔标记，不存在错位风险。
"""

import html
import os
import re
import time
from html.parser import HTMLParser

_MS_ENDPOINT = "https://api.cognitive.microsofttranslator.com/translate"
MAX_CHUNK_CHARS = 3500
MAX_TEXTS_PER_REQUEST = 50
_SKIP_TAGS = {"script", "style", "head", "title", "noscript"}


class TranslationError(Exception):
    pass


class TranslationRateLimited(TranslationError):
    pass


def _is_cjk(char: str) -> bool:
    return "\u4e00" <= char <= "\u9fff" or "\u3400" <= char <= "\u4dbf"


def _is_mostly_chinese(text: str) -> bool:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    return sum(1 for c in letters if _is_cjk(c)) / len(letters) > 0.5


def _is_url_or_email(text: str) -> bool:
    stripped = text.strip()
    if re.fullmatch(r"https?://\S+", stripped):
        return True
    if re.fullmatch(r"[\w.+-]+@[\w-]+[\w.]+", stripped):
        return True
    return False


def _api_key() -> str:
    return os.environ.get("MAIL_MS_TRANSLATOR_KEY", "").strip()


def _api_region() -> str:
    return os.environ.get("MAIL_MS_TRANSLATOR_REGION", "").strip()


def _api_url() -> str:
    override = os.environ.get("MAIL_MS_TRANSLATOR_ENDPOINT", "").strip()
    return override.rstrip("/") if override else _MS_ENDPOINT


def _target_code(target: str) -> str:
    """把调用方传的 zh-CN 这类目标码转成微软的目标码（zh-Hans）。"""
    code = (target or "zh").strip().replace("_", "-").lower()
    if code.startswith("zh"):
        return "zh-Hans"
    return code


def _ms_translate(texts, target: str = "zh-CN", http_post=None):
    """一次微软翻译请求翻一组文本，按顺序原样返回（译文列表，检测到的源语言）。"""
    key = _api_key()
    if not key:
        raise TranslationError("未配置微软翻译密钥，请在服务器环境文件里设置 MAIL_MS_TRANSLATOR_KEY")
    if http_post is None:
        import requests

        http_post = requests.post
    headers = {
        "Ocp-Apim-Subscription-Key": key,
        "Content-Type": "application/json",
    }
    region = _api_region()
    if region and region.lower() != "global":
        headers["Ocp-Apim-Subscription-Region"] = region
    params = {"api-version": "3.0", "to": _target_code(target)}
    body = [{"Text": t} for t in texts]
    url = _api_url()
    last_error = None
    for attempt in range(3):
        try:
            resp = http_post(url, json=body, headers=headers, params=params, timeout=30)
        except Exception as exc:
            last_error = TranslationError(f"微软翻译请求失败，请稍后再试: {exc}")
            if attempt < 2:
                time.sleep(1 + attempt * 2)
                continue
            raise last_error
        if resp.status_code == 200:
            try:
                items = resp.json() or []
                out = []
                detected = None
                for item in items:
                    trans = (item.get("translations") or [{}])[0]
                    out.append(trans.get("text", ""))
                    if detected is None:
                        det = item.get("detectedLanguage") or {}
                        detected = det.get("language")
            except Exception as exc:
                raise TranslationError(f"翻译结果解析失败: {exc}")
            if len(out) != len(texts):
                raise TranslationError("翻译结果数量与原文不符")
            return out, (detected.lower() if detected else None)
        if resp.status_code == 429:
            last_error = TranslationRateLimited("微软翻译限流，请稍后再试")
            if attempt < 2:
                time.sleep(1 + attempt * 2)
                continue
            raise last_error
        if resp.status_code == 401:
            raise TranslationError("微软翻译密钥无效，请检查服务器上的 MAIL_MS_TRANSLATOR_KEY")
        if resp.status_code == 403:
            raise TranslationError("微软翻译额度用完或区域不对：请检查 MAIL_MS_TRANSLATOR_REGION 是否与资源位置一致，或升级 S1")
        err = ""
        try:
            err = (resp.json() or {}).get("error", {}).get("message", "")
        except Exception:
            pass
        raise TranslationError(
            f"微软翻译返回 {resp.status_code}" + (f": {err}" if err else "")
        )
    raise last_error or TranslationError("翻译失败")


def _split_text(text: str, max_chars: int = MAX_CHUNK_CHARS):
    """按段落累积分段，超长段落再按行、按字符切，绝不把一句话拦腰截断到
    无法还原——分段只影响请求次数，不影响拼接结果。"""
    chunks, current = [], ""
    for para in re.split(r"(\n\s*\n)", text):
        if len(current) + len(para) <= max_chars:
            current += para
            continue
        if current:
            chunks.append(current)
            current = ""
        if len(para) <= max_chars:
            current = para
            continue
        # 超长段落：先按行切，行仍超长则按字符硬切。
        for line in para.splitlines(keepends=True):
            if len(current) + len(line) <= max_chars:
                current += line
                continue
            if current:
                chunks.append(current)
                current = ""
            while len(line) > max_chars:
                chunks.append(line[:max_chars])
                line = line[max_chars:]
            current = line
    if current:
        chunks.append(current)
    return chunks or [""]


def translate_text(text: str, target: str = "zh-CN", http_post=None) -> tuple:
    """翻译纯文本。返回 (译文, 检测到的源语言)。已是中文则原样返回。"""
    if not text or not text.strip():
        return text, None
    if _is_mostly_chinese(text):
        return text, "zh"
    chunks = _split_text(text)
    translated_parts, detected = [], None
    for i in range(0, len(chunks), MAX_TEXTS_PER_REQUEST):
        parts, group_detected = _ms_translate(
            chunks[i : i + MAX_TEXTS_PER_REQUEST], target=target, http_post=http_post
        )
        translated_parts.extend(parts)
        detected = detected or group_detected
    return "".join(translated_parts), detected


class _TranslateNode:
    __slots__ = ("tag", "attrs", "children", "parent", "text")

    def __init__(self, tag=None, attrs=None, parent=None, text=None):
        self.tag = tag
        self.attrs = dict(attrs or [])
        self.children = []
        self.parent = parent
        self.text = text


class _TranslateTreeParser(HTMLParser):
    _VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
             "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _TranslateNode(tag="root")
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = _TranslateNode(tag=tag, attrs=attrs, parent=self.stack[-1])
        self.stack[-1].children.append(node)
        if tag not in self._VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        node = _TranslateNode(tag=tag, attrs=attrs, parent=self.stack[-1])
        self.stack[-1].children.append(node)

    def handle_endtag(self, tag):
        for idx in range(len(self.stack) - 1, 0, -1):
            if self.stack[idx].tag == tag:
                del self.stack[idx:]
                break

    def handle_data(self, data):
        if data:
            self.stack[-1].children.append(_TranslateNode(parent=self.stack[-1], text=data))


def _serialize_translate_node(node) -> str:
    if node.tag is None:
        return html.escape(node.text or "", quote=False)
    attrs = "".join(f' {name}="{html.escape(value, quote=True)}"' for name, value in node.attrs.items())
    if node.tag in _TranslateTreeParser._VOID:
        return f"<{node.tag}{attrs}>"
    inner = "".join(_serialize_translate_node(child) for child in node.children)
    return f"<{node.tag}{attrs}>{inner}</{node.tag}>"


def _collect_text_nodes(node, ancestors, out):
    for child in node.children:
        if child.tag is None:
            if any(a in _SKIP_TAGS for a in ancestors):
                continue
            text = child.text or ""
            if not text.strip():
                continue
            if _is_url_or_email(text):
                continue
            if _is_mostly_chinese(text):
                continue
            out.append(child)
        else:
            _collect_text_nodes(child, ancestors + [child.tag], out)


def _apply_leading_trailing(original: str, translated: str) -> str:
    leading = re.match(r"^\s*", original).group(0)
    trailing = re.search(r"\s*$", original).group(0)
    return f"{leading}{translated.strip()}{trailing}"


def translate_html(html_content: str, target: str = "zh-CN", http_post=None) -> tuple:
    """翻译 HTML 邮件：只翻文本节点，标签、属性、链接、图片原样保留。

    文本节点按微软多文本接口成组发送，返回按顺序一一贴回，不拼
    分隔标记，不存在错位风险。返回 (译后 HTML, 检测到的源语言)。
    """
    parser = _TranslateTreeParser()
    parser.feed(html_content or "")
    nodes = []
    _collect_text_nodes(parser.root, [], nodes)
    if not nodes:
        return html_content, None
    detected = None
    for i in range(0, len(nodes), MAX_TEXTS_PER_REQUEST):
        batch = nodes[i : i + MAX_TEXTS_PER_REQUEST]
        texts = [(n.text or "").strip() for n in batch]
        parts, batch_detected = _ms_translate(texts, target=target, http_post=http_post)
        detected = detected or batch_detected
        for node, part in zip(batch, parts):
            node.text = _apply_leading_trailing(node.text or "", part)
    return "".join(_serialize_translate_node(child) for child in parser.root.children), detected


def translate_mail_body(body: str, body_type: str, target: str = "zh-CN", http_post=None) -> tuple:
    """按正文类型分发。返回 (译后正文, 是否已是中文, 检测到的源语言)。"""
    if "html" in (body_type or "").lower():
        translated, detected = translate_html(body, target=target, http_post=http_post)
        return translated, False, detected
    if _is_mostly_chinese(body or ""):
        return body, True, "zh"
    translated, detected = translate_text(body, target=target, http_post=http_post)
    return translated, False, detected
