#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
静态扫描大型单文件 Flask/Python Web 脚本，输出重构前盘点信息。
用途：
- imports
- 顶级函数/类
- Flask 路由
- render_template 调用
- 全局变量
- SMTP 相关函数/类
- 启动入口
- request/form/json/files 使用
- app 创建方式

用法：
    python3 scan_app.py /Users/xiaolongnvtaba/Downloads/app.py
"""

import ast
import json
import sys
from pathlib import Path


SMTP_KEYWORDS = {
    "smtplib",
    "SMTP",
    "SMTP_SSL",
    "starttls",
    "login",
    "sendmail",
    "send_message",
    "imaplib",
    "poplib",
    "MIMEText",
    "MIMEMultipart",
    "MIMEBase",
    "MIMEApplication",
    "encoders",
}


ROUTE_DECORATOR_ATTRS = {"route", "get", "post", "put", "delete", "patch"}


def get_full_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = get_full_name(node.value)
        if left:
            return f"{left}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Call):
        return get_full_name(node.func)
    return None


def literal_value(node):
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def unparse_node(node):
    try:
        return ast.unparse(node)
    except Exception:
        return None


class FunctionBodyScanner(ast.NodeVisitor):
    def __init__(self):
        self.calls = []
        self.render_templates = []
        self.render_template_strings = []
        self.request_form_fields = []
        self.request_args_fields = []
        self.request_json_accesses = []
        self.request_files_fields = []
        self.smtp_signals = []
        self.return_kinds = []
        self.global_reads = set()
        self.global_writes = set()

    def visit_Call(self, node):
        call_name = get_full_name(node.func)
        self.calls.append({
            "lineno": getattr(node, "lineno", None),
            "call": call_name,
            "code": unparse_node(node),
        })

        if call_name == "render_template":
            tpl = None
            if node.args:
                tpl = literal_value(node.args[0])
            self.render_templates.append({
                "lineno": getattr(node, "lineno", None),
                "template": tpl,
                "code": unparse_node(node),
            })

        if call_name == "render_template_string":
            self.render_template_strings.append({
                "lineno": getattr(node, "lineno", None),
                "code": unparse_node(node),
            })

        if call_name and any(k.lower() in call_name.lower() for k in SMTP_KEYWORDS):
            self.smtp_signals.append({
                "lineno": getattr(node, "lineno", None),
                "type": "call",
                "name": call_name,
                "code": unparse_node(node),
            })

        self.generic_visit(node)

    def visit_Subscript(self, node):
        text = unparse_node(node)

        if text:
            if text.startswith("request.form["):
                self.request_form_fields.append({
                    "lineno": getattr(node, "lineno", None),
                    "expr": text,
                })
            elif text.startswith("request.args["):
                self.request_args_fields.append({
                    "lineno": getattr(node, "lineno", None),
                    "expr": text,
                })
            elif text.startswith("request.files["):
                self.request_files_fields.append({
                    "lineno": getattr(node, "lineno", None),
                    "expr": text,
                })

        self.generic_visit(node)

    def visit_Attribute(self, node):
        text = unparse_node(node)
        if text in ("request.json",):
            self.request_json_accesses.append({
                "lineno": getattr(node, "lineno", None),
                "expr": text,
            })

        if text and any(k.lower() in text.lower() for k in SMTP_KEYWORDS):
            self.smtp_signals.append({
                "lineno": getattr(node, "lineno", None),
                "type": "attr",
                "name": text,
                "code": text,
            })

        self.generic_visit(node)

    def visit_Return(self, node):
        value_text = unparse_node(node.value) if node.value else None
        kind = "unknown"
        if value_text:
            if "render_template(" in value_text:
                kind = "render_template"
            elif "jsonify(" in value_text:
                kind = "jsonify"
            elif "redirect(" in value_text:
                kind = "redirect"
            elif "send_file(" in value_text or "send_from_directory(" in value_text:
                kind = "file"
            elif value_text.startswith(("'", '"', "f'", 'f"')):
                kind = "string"
            elif value_text.startswith(("(", "{", "[")):
                kind = "literal"
        self.return_kinds.append({
            "lineno": getattr(node, "lineno", None),
            "kind": kind,
            "value": value_text,
        })
        self.generic_visit(node)


class AppScanner(ast.NodeVisitor):
    def __init__(self, source):
        self.source = source
        self.imports = []
        self.top_level_functions = []
        self.top_level_classes = []
        self.global_variables = []
        self.route_functions = []
        self.render_template_calls = []
        self.smtp_related_functions = []
        self.startup_entries = []
        self.app_creations = []
        self.blueprint_creations = []
        self.module_level_calls = []

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append({
                "type": "import",
                "module": alias.name,
                "asname": alias.asname,
                "lineno": node.lineno,
            })

    def visit_ImportFrom(self, node):
        self.imports.append({
            "type": "from",
            "module": node.module,
            "names": [{"name": a.name, "asname": a.asname} for a in node.names],
            "lineno": node.lineno,
        })

    def scan_top_level_assign(self, node):
        targets = []
        for t in node.targets:
            if isinstance(t, ast.Name):
                targets.append(t.id)
        if not targets:
            return

        value_text = unparse_node(node.value)
        for name in targets:
            self.global_variables.append({
                "name": name,
                "lineno": node.lineno,
                "value": value_text,
            })

            if isinstance(node.value, ast.Call):
                func_name = get_full_name(node.value.func)
                if func_name == "Flask":
                    self.app_creations.append({
                        "name": name,
                        "lineno": node.lineno,
                        "expr": value_text,
                    })
                elif func_name == "Blueprint":
                    self.blueprint_creations.append({
                        "name": name,
                        "lineno": node.lineno,
                        "expr": value_text,
                    })

    def visit_Assign(self, node):
        if isinstance(getattr(node, "parent", None), ast.Module):
            self.scan_top_level_assign(node)

    def visit_AnnAssign(self, node):
        if isinstance(getattr(node, "parent", None), ast.Module):
            if isinstance(node.target, ast.Name):
                self.global_variables.append({
                    "name": node.target.id,
                    "lineno": node.lineno,
                    "value": unparse_node(node.value) if node.value else None,
                })

    def visit_Expr(self, node):
        if isinstance(getattr(node, "parent", None), ast.Module):
            if isinstance(node.value, ast.Call):
                self.module_level_calls.append({
                    "lineno": node.lineno,
                    "call": get_full_name(node.value.func),
                    "code": unparse_node(node.value),
                })

    def _extract_route_info(self, fn_node):
        routes = []
        for dec in fn_node.decorator_list:
            if isinstance(dec, ast.Call):
                full = get_full_name(dec.func)
                attr = full.split(".")[-1] if full else None
                if attr in ROUTE_DECORATOR_ATTRS:
                    route_path = None
                    methods = None
                    if dec.args:
                        route_path = literal_value(dec.args[0])
                    for kw in dec.keywords:
                        if kw.arg == "methods":
                            methods = literal_value(kw.value)
                    routes.append({
                        "decorator": unparse_node(dec),
                        "decorator_name": full,
                        "path": route_path,
                        "methods": methods,
                        "lineno": dec.lineno,
                    })
        return routes

    def visit_FunctionDef(self, node):
        if isinstance(getattr(node, "parent", None), ast.Module):
            routes = self._extract_route_info(node)

            scanner = FunctionBodyScanner()
            scanner.visit(node)

            func_info = {
                "name": node.name,
                "lineno": node.lineno,
                "end_lineno": getattr(node, "end_lineno", None),
                "args": [a.arg for a in node.args.args],
                "decorators": [unparse_node(d) for d in node.decorator_list],
                "routes": routes,
                "returns": scanner.return_kinds,
                "render_templates": scanner.render_templates,
                "render_template_strings": scanner.render_template_strings,
                "request_form_fields": scanner.request_form_fields,
                "request_args_fields": scanner.request_args_fields,
                "request_json_accesses": scanner.request_json_accesses,
                "request_files_fields": scanner.request_files_fields,
                "smtp_signals": scanner.smtp_signals,
                "calls_sample": scanner.calls[:30],
            }

            self.top_level_functions.append(func_info)

            if routes:
                self.route_functions.append(func_info)

            if scanner.render_templates:
                self.render_template_calls.append({
                    "function": node.name,
                    "lineno": node.lineno,
                    "calls": scanner.render_templates,
                })

            if scanner.smtp_signals:
                self.smtp_related_functions.append({
                    "function": node.name,
                    "lineno": node.lineno,
                    "signals": scanner.smtp_signals,
                })

        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node):
        if isinstance(getattr(node, "parent", None), ast.Module):
            methods = []
            smtp_related = False
            route_methods = []

            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method_scanner = FunctionBodyScanner()
                    method_scanner.visit(item)

                    method_info = {
                        "name": item.name,
                        "lineno": item.lineno,
                        "end_lineno": getattr(item, "end_lineno", None),
                        "decorators": [unparse_node(d) for d in item.decorator_list],
                        "routes": self._extract_route_info(item),
                        "render_templates": method_scanner.render_templates,
                        "smtp_signals": method_scanner.smtp_signals,
                    }
                    methods.append(method_info)

                    if method_info["routes"]:
                        route_methods.append(method_info)
                    if method_info["smtp_signals"]:
                        smtp_related = True

            self.top_level_classes.append({
                "name": node.name,
                "lineno": node.lineno,
                "end_lineno": getattr(node, "end_lineno", None),
                "bases": [unparse_node(b) for b in node.bases],
                "methods": methods,
            })

            if route_methods:
                self.route_functions.append({
                    "class": node.name,
                    "lineno": node.lineno,
                    "methods": route_methods,
                })

            if smtp_related:
                self.smtp_related_functions.append({
                    "class": node.name,
                    "lineno": node.lineno,
                    "methods": [
                        m for m in methods if m["smtp_signals"]
                    ],
                })

        self.generic_visit(node)

    def detect_startup(self, tree):
        for node in tree.body:
            if isinstance(node, ast.If):
                test_text = unparse_node(node.test)
                if test_text == "__name__ == '__main__'" or test_text == '__name__ == "__main__"':
                    block_calls = []
                    for stmt in node.body:
                        for sub in ast.walk(stmt):
                            if isinstance(sub, ast.Call):
                                block_calls.append({
                                    "lineno": getattr(sub, "lineno", None),
                                    "call": get_full_name(sub.func),
                                    "code": unparse_node(sub),
                                })
                    self.startup_entries.append({
                        "lineno": node.lineno,
                        "test": test_text,
                        "calls": block_calls,
                    })


def attach_parents(node):
    for child in ast.iter_child_nodes(node):
        child.parent = node
        attach_parents(child)


def build_summary(result):
    return {
        "imports_count": len(result["imports"]),
        "top_level_function_count": len(result["top_level_functions"]),
        "top_level_class_count": len(result["top_level_classes"]),
        "route_count": sum(
            len(f.get("routes", []))
            for f in result["top_level_functions"]
        ),
        "route_function_count": len([
            f for f in result["top_level_functions"] if f.get("routes")
        ]),
        "render_template_function_count": len(result["render_template_calls"]),
        "global_variable_count": len(result["global_variables"]),
        "smtp_related_function_or_class_count": len(result["smtp_related"]),
        "startup_entry_count": len(result["startup_entries"]),
        "app_creation_count": len(result["app_creations"]),
        "blueprint_creation_count": len(result["blueprint_creations"]),
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scan_app.py /path/to/app.py", file=sys.stderr)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(2)

    code = path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(code)
    attach_parents(tree)

    scanner = AppScanner(code)
    scanner.visit(tree)
    scanner.detect_startup(tree)

    result = {
        "file": str(path),
        "summary": {},
        "imports": scanner.imports,
        "app_creations": scanner.app_creations,
        "blueprint_creations": scanner.blueprint_creations,
        "global_variables": scanner.global_variables,
        "top_level_functions": scanner.top_level_functions,
        "top_level_classes": scanner.top_level_classes,
        "route_functions": scanner.route_functions,
        "render_template_calls": scanner.render_template_calls,
        "smtp_related": scanner.smtp_related_functions,
        "startup_entries": scanner.startup_entries,
        "module_level_calls": scanner.module_level_calls,
    }
    result["summary"] = build_summary(result)

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()