"""macOS deny-by-default worker profile and process-group containment.

No unsandboxed fallback. Fixed host-admitted Python worker, JSON stdin, scrubbed
environment. This profile is platform-specific, not container/cloud isolation.
"""

import asyncio
import json
import os
from pathlib import Path
import signal
import sys
import tempfile

from .runtime import AccessDenied, GuardError
from .orchestration import Admission


class SandboxedPythonWorker:
    def __init__(self, admission: Admission, *, timeout=5, output_limit=1_048_576):
        if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
            raise ValueError("sandbox_profile_unavailable")
        if type(timeout) not in (int,float) or not 0<timeout<=120 or type(output_limit) is not int or not 1<=output_limit<=1_048_576:
            raise ValueError("invalid_worker_limits")
        admission.verify()
        self.admission, self.timeout, self.output_limit = admission, timeout, output_limit
        self.last_pid = None

    def _profile(self, working, worker_path=None):
        paths = {"/System", "/usr", "/Library/Apple", str(Path(sys.base_prefix).resolve()), str(Path(sys.prefix).resolve())}
        reads = " ".join("(subpath "+json.dumps(path)+")" for path in paths)
        literals = " ".join("(literal "+json.dumps(path)+")" for path in
                            (worker_path or str(Path(self.admission.path).resolve()),str(Path(sys.executable).resolve()),
                             "/dev/null","/dev/random","/dev/urandom","/private/etc/localtime"))
        return ('(version 1)(deny default)(allow process-exec)(allow sysctl-read)'
                '(allow file-read-metadata)(allow file-read* (literal "/"))'
                '(allow file-read* '+reads+' '+literals+' (subpath '+json.dumps(working)+'))'
                '(allow file-write* (subpath '+json.dumps(working)+') (literal "/dev/null"))')

    async def call(self, operation):
        content=self.admission.read_verified()
        with tempfile.TemporaryDirectory(prefix="enkstein-worker-") as directory:
            root=Path(directory).resolve()
            snapshot=root/'admitted-worker.py'
            snapshot.write_bytes(content)
            snapshot.chmod(0o400)
            work=root/'work';work.mkdir(mode=0o700)
            working = str(work)
            process = await asyncio.create_subprocess_exec(
                "/usr/bin/sandbox-exec", "-p", self._profile(working,str(snapshot)), str(Path(sys.executable).resolve()), "-I", "-B",
                str(snapshot), cwd=working,
                env={"PATH":"/usr/bin:/bin","LANG":"C.UTF-8"},
                stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            self.last_pid = process.pid
            async def read(reader):
                data = bytearray()
                while True:
                    chunk = await reader.read(8192)
                    if not chunk:
                        return bytes(data)
                    data.extend(chunk)
                    if len(data)>self.output_limit:
                        raise AccessDenied("worker_output_limit")
            async def write():
                process.stdin.write(operation.payload_json.encode())
                await process.stdin.drain()
                process.stdin.close()
            tasks = [asyncio.create_task(write()),asyncio.create_task(read(process.stdout)),asyncio.create_task(read(process.stderr))]
            try:
                _,stdout,stderr = await asyncio.wait_for(asyncio.gather(*tasks),self.timeout)
                await asyncio.wait_for(process.wait(),self.timeout)
                if process.returncode:
                    raise AccessDenied("worker_failed")
                return json.loads(stdout)
            except BaseException as error:
                if process.returncode is None:
                    try:
                        os.killpg(process.pid,signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await process.wait()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks,return_exceptions=True)
                if isinstance(error,asyncio.CancelledError):
                    raise
                raise GuardError("worker_denied_or_terminated") from None
