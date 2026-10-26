"""邮件翻译服务：本地 LibreTranslate（默认 http://127.0.0.1:5000/translate）。

手动点翻译时才调用，邮件内容只在那一刻发给本机翻译服务；不自动
翻译、不存翻译结果，页面刷新后再次点翻译会重新请求。模型跑在本
机，不经过任何第三方翻译商，也就没有 Google 免费接口那种按 IP 的
429 限流；代价是翻译质量比 Google 略差，且首次启动要下载语言模型，
模型没下完之前翻译会报服务未就绪，等一会儿再试即可。

翻译服务地址可用环境变量 MAIL_TRANSLATE_URL 覆盖（默认指向本机
LibreTranslate 的 /translate 端口，install.sh 会一并装好该服务）。
"""

import html
import os
import re
import time
from html.parser import HTMLParser

LT_URL = os.environ.get("MAIL_TRANSLATE_URL", "http://127.0.0.1:5000/translate").rstrip("/")
MAX_CHUNK_CHARS = 3500
# 批量翻译文本节点时的分隔标记：无意义的字母数字串，翻译方通常原样保留。
# 万一分隔后数量对不上，自动退回逐节点翻译，绝不把错位的译文拼回去。
_BATCH_SEP = "TRANSLATESEP12345"
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
    if re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.]+", stripped):
        return True
    return False


def _target_code(target: str) -> str:
    """把调用方传的 zh-CN 这类目标码转成 LibreTranslate 的语言码（zh）。"""
    code = (target or "zh").strip().lower().replace("_", "-").split("-")[0]
    return code or "zh"


def _parse_lt_response(data):
    """解析 LibreTranslate 返回：{translatedText, detectedLanguage?}。"""
    if not isinstance(data, dict):
        raise TranslationError("翻译结果解析失败")
    translated = data.get("translatedText")
    if isinstance(translated, list):
        translated = "".join(str(t) for t in translated)
    if not isinstance(translated, str):
        raise TranslationError("翻译结果解析失败")
    detected = None
    det = data.get("detectedLanguage")
    if isinstance(det, dict):
        detected = det.get("language")
    elif isinstance(det, list) and det and isinstance(det[0], dict):
        detected = det[0].get("language")
    return translated, detected


def _lt_translate(text: str, target: str = "zh-CN", http_post=None) -> tuple:
    """翻译一段文本（调用方负责分段，单段不超过 MAX_CHUNK_CHARS）。"""
    if http_post is None:
        import requests

        http_post = requests.post
    payload = {"q": text, "source": "auto", "target": _target_code(target), "format": "text"}
    last_error = None
    for attempt in range(3):
        try:
            resp = http_post(LT_URL, json=payload, timeout=50)
        except Exception as exc:  # 本地服务没起来、模型没下完都会走到这里
            last_error = TranslationError(f"本地翻译服务未就绪，请稍后再试: {exc}")
            if attempt < 2:
                time.sleep(1 + attempt * 2)
                continue
            raise last_error
        if resp.status_code == 429:
            last_error = TranslationRateLimited("本地翻译服务限流，请稍后再试")
            if attempt < 2:
                time.sleep(1 + attempt * 2)
                continue
            raise last_error
        if resp.status_code != 200:
            err = ""
            try:
                err = (resp.json() or {}).get("error", "")
            except Exception:
                pass
            raise TranslationError(
                f"本地翻译服务返回 {resp.status_code}" + (f": {err}" if err else "")
            )
        try:
            return _parse_lt_response(resp.json())
        except TranslationError:
            raise
        except Exception as exc:
            raise TranslationError(f"翻译结果解析失败: {exc}")
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
    translated_parts, detected = [], None
    for chunk in _split_text(text):
        part, chunk_detected = _lt_translate(chunk, target=target, http_post=http_post)
        translated_parts.append(part)
        detected = detected or chunk_detected
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

    文本节点先批量翻译（分隔标记拼接），分隔对不上时自动退回逐节点
    翻译；长节点内部按段落分段。返回 (译后 HTML, 检测到的源语言)。
    """
    parser = _TranslateTreeParser()
    parser.feed(html_content or "")
    nodes = []
    _collect_text_nodes(parser.root, [], nodes)
    if not nodes:
        return html_content, None
    detected = None
    # 批量：按总长度分组，分隔标记拼接一次请求。
    batches, current, current_len = [], [], 0
    for node in nodes:
        text = (node.text or "").strip()
        if current and current_len + len(text) + len(_BATCH_SEP) > MAX_CHUNK_CHARS:
            batches.append(current)
            current, current_len = [], 0
        current.append(node)
        current_len += len(text) + len(_BATCH_SEP)
    if current:
        batches.append(current)
    for batch in batches:
        joined = f"\n{_BATCH_SEP}\n".join((n.text or "").strip() for n in batch)
        try:
            translated_joined, batch_detected = _lt_translate(joined, target=target, http_post=http_post)
        except TranslationError:
            raise
        detected = detected or batch_detected
        parts = [p.strip() for p in translated_joined.split(_BATCH_SEP)]
        if len(parts) != len(batch):
            # 分隔标记被翻译方改动：退回逐节点翻译，绝不错位拼接。
            for node in batch:
                part, node_detected = translate_text(node.text or "", target=target, http_post=http_post)
                node.text = _apply_leading_trailing(node.text or "", part)
                detected = detected or node_detected
            continue
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
