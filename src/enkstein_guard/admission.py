"""Declared-capability static check for admitted Python components.

The operator declares what a pinned component may do (``network``,
``process``, ``dynamic_code``, ``native``, ``filesystem_write``,
``environment``). Admission rejects components whose source uses an
undeclared capability. This is a heuristic AST check that complements hash
pinning and runtime containment. It is not malware classification: code that
hides behaviour (for example through data-driven imports the checker cannot
resolve) is reported as ``dynamic_code`` when recognised and can otherwise be
missed. See docs/data-protection.md and the attack-scenario evidence.
"""
from __future__ import annotations

import ast
from functools import lru_cache
import hashlib

CAPABILITIES = frozenset({"network", "process", "dynamic_code", "native", "filesystem_write", "environment"})
_MODULES = {
    "network": ("socket", "ssl", "http", "urllib", "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc",
                "requests", "httpx", "aiohttp", "websocket", "websockets", "asyncio.streams", "paramiko"),
    "process": ("subprocess", "multiprocessing", "pty", "os.system", "os.popen", "os.exec", "os.spawn", "os.fork",
                "concurrent.futures.process"),
    "dynamic_code": ("importlib", "runpy", "marshal", "pickle", "code", "codeop", "zipimport"),
    "native": ("ctypes", "cffi", "mmap", "_ctypes"),
    "environment": ("os.environ", "os.getenv", "os.putenv"),
}
_DYNAMIC_CALLS = frozenset({"eval", "exec", "compile", "__import__", "getattr", "globals", "locals", "vars",
                            "setattr", "delattr", "breakpoint"})
_OS_PROCESS = frozenset({"system", "popen", "execv", "execve", "execl", "execle", "execlp", "execvp", "execvpe",
                         "spawnl", "spawnv", "spawnve", "fork", "forkpty", "posix_spawn", "posix_spawnp", "kill", "killpg"})
_OS_WRITE = frozenset({"remove", "unlink", "rmdir", "removedirs", "rename", "renames", "replace", "mkdir",
                       "makedirs", "chmod", "chown", "symlink", "link", "truncate", "write"})
_WRITE_METHODS = frozenset({"write_text", "write_bytes", "unlink", "rmdir", "mkdir", "touch", "rename", "replace",
                            "chmod", "symlink_to", "hardlink_to"})


def _classify_module(name):
    found = set()
    for capability, prefixes in _MODULES.items():
        if any(name == prefix or name.startswith(prefix + ".") for prefix in prefixes):
            found.add(capability)
    return found


@lru_cache(maxsize=256)
def _scan(digest, source):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return frozenset({"unparseable"})
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found |= _classify_module(alias.name)
                if alias.name == "shutil":
                    found.add("filesystem_write")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            found |= _classify_module(module)
            for alias in node.names:
                found |= _classify_module(module + "." + alias.name)
                if module == "os" and alias.name in _OS_PROCESS:
                    found.add("process")
                if module == "os" and alias.name in _OS_WRITE:
                    found.add("filesystem_write")
                if module == "os" and alias.name in ("environ", "getenv", "putenv"):
                    found.add("environment")
            if module == "shutil":
                found.add("filesystem_write")
        elif isinstance(node, ast.Call):
            function = node.func
            if isinstance(function, ast.Name):
                if function.id in _DYNAMIC_CALLS:
                    found.add("dynamic_code")
                if function.id == "open" and _writes(node):
                    found.add("filesystem_write")
            elif isinstance(function, ast.Attribute):
                owner = function.value.id if isinstance(function.value, ast.Name) else None
                if owner == "os" and function.attr in _OS_PROCESS:
                    found.add("process")
                if owner == "os" and function.attr in _OS_WRITE:
                    found.add("filesystem_write")
                if owner == "os" and function.attr in ("getenv", "putenv"):
                    found.add("environment")
                if function.attr in _WRITE_METHODS:
                    found.add("filesystem_write")
                if function.attr == "open" and _writes(node):
                    found.add("filesystem_write")
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
                found.add("environment")
            if node.attr in ("__builtins__", "__globals__", "__subclasses__", "__code__", "__dict__", "__import__"):
                found.add("dynamic_code")
        elif isinstance(node, ast.Name) and node.id in ("__builtins__", "__loader__", "__spec__"):
            found.add("dynamic_code")
    return frozenset(found)


def _writes(call):
    mode = None
    if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant):
        mode = call.args[1].value
    for keyword in call.keywords:
        if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
            mode = keyword.value.value
    if mode is None:
        return len(call.args) >= 2 or any(k.arg == "mode" for k in call.keywords)
    return isinstance(mode, str) and any(flag in mode for flag in "wax+")


def scan_python(source: bytes) -> frozenset:
    """Capabilities used by Python source (heuristic; see module docstring)."""
    return _scan(hashlib.sha256(source).hexdigest(), source)


def undeclared(source: bytes, declared) -> frozenset:
    declared = frozenset(declared)
    if not declared <= CAPABILITIES:
        raise ValueError("unknown_component_capability")
    return scan_python(source) - declared
