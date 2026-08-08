#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
from pathlib import Path

TARGETS = [
    "moemail_api_required",
    "login_required",
    "admin_required",
    "get_valid_per_page",
    "parse_request_timestamp",
    "get_managed_mailbox_by_id",
    "get_managed_domains",
    "get_primary_domain",
    "delete_managed_domain",
    "set_primary_domain",
    "extract_code_from_body",
]


def extract_function(lines, func_name):
    pattern = re.compile(rf'^def\s+{re.escape(func_name)}\s*\(')
    start = None
    for i, line in enumerate(lines):
        if pattern.match(line):
            start = i
            break
    if start is None:
        return None

    collected = [lines[start]]
    for j in range(start + 1, len(lines)):
        line = lines[j]
        if line.startswith('def ') or line.startswith('class ') or line.startswith('@app.route'):
            break
        if line.startswith('@') and not line.startswith('    '):
            break
        collected.append(line)
    return ''.join(collected)


def main():
    if len(sys.argv) != 2:
        print('Usage: python3 extract_functions.py /path/to/app.py', file=sys.stderr)
        sys.exit(1)

    app_path = Path(sys.argv[1])
    lines = app_path.read_text(encoding='utf-8', errors='replace').splitlines(keepends=True)
    out_dir = app_path.parent / 'extracted_functions'
    out_dir.mkdir(exist_ok=True)

    found = []
    missing = []
    for name in TARGETS:
        text = extract_function(lines, name)
        if text is None:
            missing.append(name)
            continue
        (out_dir / f'{name}.py').write_text(text, encoding='utf-8')
        found.append(name)

    (out_dir / 'SUMMARY.txt').write_text(
        'FOUND:\n' + '\n'.join(found) + '\n\nMISSING:\n' + '\n'.join(missing) + '\n',
        encoding='utf-8'
    )
    print(out_dir)


if __name__ == '__main__':
    main()
