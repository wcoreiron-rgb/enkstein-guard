"""Trusted bootstrap runner for the local Guard service.

Factory code is operator-controlled Python, never supplied by an agent request.
"""
import argparse
import asyncio
import importlib
import inspect
import json
import os
from pathlib import Path
import signal
import socket
import stat

from .service import GuardService


def _prepare_socket(path):
    # Lock is held by serve() before checking/removing a stale socket.
    if not path.exists() and not path.is_symlink():
        return
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("unsafe_existing_service_path")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(1)
    try:
        probe.connect(str(path))
    except ConnectionRefusedError:
        path.unlink()
    else:
        raise ValueError("service_already_running")
    finally:
        probe.close()


async def serve(factory, socket_path, stop=None):
    import fcntl
    path = Path(socket_path)
    parent = path.parent
    info = parent.stat()
    if parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o700,0o710) or (stat.S_IMODE(info.st_mode)==0o710 and info.st_gid != os.getgid()):
        raise ValueError("private_service_directory_required")
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(parent / (path.name + ".lock"), flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("unsafe_service_lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _prepare_socket(path)
        runtime = factory()
        if inspect.isawaitable(runtime):
            runtime = await runtime
        service = runtime if isinstance(runtime, GuardService) else GuardService(runtime, path)
        if service.path != path:
            raise ValueError("factory_socket_mismatch")
        await service.start()
        stopped = stop or asyncio.Event()
        loop = asyncio.get_running_loop()
        signals = []
        try:
            if stop is None:
                for signum in (signal.SIGTERM, signal.SIGINT):
                    loop.add_signal_handler(signum, stopped.set)
                    signals.append(signum)
            await stopped.wait()
        finally:
            for signum in signals:
                loop.remove_signal_handler(signum)
            await service.close()
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description="Run a trusted Enkstein Guard host")
    parser.add_argument("--factory", required=True, help="Operator-controlled module:function")
    parser.add_argument("--socket", required=True)
    args = parser.parse_args()
    try:
        module, name = args.factory.split(":")
        factory = getattr(importlib.import_module(module), name)
        asyncio.run(serve(factory, args.socket))
        return 0
    except Exception:
        print(json.dumps({"status": "guard_host_failed"}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
