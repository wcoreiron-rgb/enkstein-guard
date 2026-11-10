import asyncio
from pathlib import Path
import os
import socket
import tempfile
import unittest
from enkstein_guard.daemon import serve
from enkstein_guard.service import guarded_request


@unittest.skipUnless(os.name == "posix", "Unix deployment")
class DaemonTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="egd-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "guard.sock"
        class Runtime:
            async def execute(self, credential, route, payload):
                return {"ok": True}
        self.factory = Runtime

    async def launch(self):
        stop = asyncio.Event()
        task = asyncio.create_task(serve(self.factory, self.path, stop))
        async def cleanup():
            stop.set()
            await task
        self.addAsyncCleanup(cleanup)
        for _ in range(100):
            try:
                await guarded_request(self.path, "readiness", "readiness", {})
                break
            except (FileNotFoundError, ConnectionRefusedError):
                await asyncio.sleep(.001)
        return stop, task

    async def test_start_shutdown_and_restart(self):
        stop, task = await self.launch()
        result = await guarded_request(self.path, "credential", "route", {})
        self.assertEqual(result["status"], "ok")
        stop.set()
        await task
        self.assertFalse(self.path.exists())
        await self.launch()
        self.assertEqual((await guarded_request(self.path, "credential", "route", {}))["status"], "ok")

    async def test_competing_daemon_cannot_replace_socket(self):
        await self.launch()
        with self.assertRaises(BlockingIOError):
            await serve(self.factory, self.path, asyncio.Event())
        self.assertTrue(self.path.exists())

    async def test_stale_socket_recovered(self):
        stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stale.bind(str(self.path))
        stale.close()
        await self.launch()
        self.assertEqual((await guarded_request(self.path, "credential", "route", {}))["status"], "ok")

    async def test_existing_regular_file_never_deleted(self):
        self.path.write_text("keep")
        with self.assertRaises(ValueError):
            await serve(self.factory, self.path, asyncio.Event())
        self.assertEqual(self.path.read_text(), "keep")
