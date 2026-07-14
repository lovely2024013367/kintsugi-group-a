#!/usr/bin/env python3
"""Ensure syscall_filter_end runs even when subprocess.getoutput fails."""
import json
from pathlib import Path

WHITELIST = {
    "close": [],
    "dup": [],
    "execve": [
        "/bin/sh",
        "/usr/bin/pg_dump",
        "/usr/bin/pg_dumpall",
        "/usr/bin/pg_restore",
        "/usr/bin/psql",
        "/usr/local/bin/pg_dump",
        "/usr/local/bin/pg_dumpall",
        "/usr/local/bin/pg_restore",
        "/usr/local/bin/psql",
    ],
    "lseek": [],
    "open": ["/usr/lib/python", "/usr/local/lib/python"],
    "openat": [
        "/etc/ld.so.cache",
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/proc/self/fd",
        "/usr/lib/python",
        "/usr/local/lib/python",
    ],
    "pipe": [],
    "read": [],
    "vfork": [],
    "write": [],
}

REPAIR_BODY = '''@blueprint.route("/validate_binary_path",
                 endpoint="validate_binary_path",
                 methods=["POST"])
@login_required
def validate_binary_path():
    """
    This function is used to validate the specified utilities path by
    running the utilities with their versions.
    """
    import sys
    if '/tmp/python_syscall_filter' not in sys.path:
        sys.path.insert(0, '/tmp/python_syscall_filter')
    from syscall_filter import syscall_filter_begin, syscall_filter_end

    data = None
    if hasattr(request.data, 'decode'):
        data = request.data.decode('utf-8')

    if data != '':
        data = json.loads(data)

    version_str = ''
    _syscall_whitelist = {
        'close': [],
        'dup': [],
        'execve': ['/bin/sh', '/usr/bin/pg_dump', '/usr/bin/pg_dumpall', '/usr/bin/pg_restore', '/usr/bin/psql', '/usr/local/bin/pg_dump', '/usr/local/bin/pg_dumpall', '/usr/local/bin/pg_restore', '/usr/local/bin/psql'],
        'lseek': [],
        'open': ['/usr/lib/python', '/usr/local/lib/python'],
        'openat': ['/etc/ld.so.cache', '/lib/x86_64-linux-gnu/libc.so.6', '/proc/self/fd', '/usr/lib/python', '/usr/local/lib/python'],
        'pipe': [],
        'read': [],
        'vfork': [],
        'write': [],
    }
    if 'utility_path' in data and data['utility_path'] is not None:
        binary_path = replace_binary_path(data['utility_path'])

        for utility in UTILITIES_ARRAY:
            full_path = os.path.abspath(
                os.path.join(binary_path,
                             (utility if os.name != 'nt' else
                              (utility + '.exe'))))

            try:
                if not os.path.exists(binary_path):
                    current_app.logger.warning('Invalid binary path.')
                    raise Exception()
                syscall_filter_begin(_syscall_whitelist)
                try:
                    version_string = \\
                        subprocess.getoutput('"{0}" --version'.format(full_path))
                finally:
                    syscall_filter_end(_syscall_whitelist)
                version_string.split(") ", 1)[1].split('.', 1)[0]
            except Exception:
                version_str += "<b>" + utility + ":</b> " + \\
                               "not found on the specified binary path.<br/>"
                continue

            result_str = version_string.replace(utility, '')
            version_str += "<b>" + utility + ":</b> " + result_str + "<br/>"
    else:
        return precondition_required(gettext('Invalid binary path.'))

    return make_json_response(data=gettext(version_str), status=200)'''


def patch_file(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    repairs = data if isinstance(data, list) else data.get("repairs", [])
    for repair in repairs:
        if repair.get("function_name") == "pgadmin.misc.validate_binary_path":
            repair["repair_code"] = REPAIR_BODY
            repair["whitelist"] = WHITELIST
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Patched {path}")


if __name__ == "__main__":
    base = Path("data/python/CVE-2023-5002")
    for name in ["repair/malicious_10_repairs.json", "repair_with_whitelist/malicious_10_repairs.json"]:
        p = base / name
        if p.exists():
            patch_file(p)
