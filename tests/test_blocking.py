import asyncio
import threading
import unittest
from enkstein_guard.blocking import BoundedBlockingTransport
from enkstein_guard.runtime import UnavailableBeforeDispatch


class BlockingTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_http_work_holds_capacity_until_thread_finishes(self):
        transport=BoundedBlockingTransport(maximum=1)
        release=threading.Event()
        started=threading.Event()
        finished=threading.Event()
        self.addCleanup(transport.close)
        self.addCleanup(release.set)
        def blocking():
            started.set()
            release.wait(2)
            finished.set()
            return "done"
        task=asyncio.create_task(transport.run(blocking))
        for _ in range(100):
            if started.is_set():break
            await asyncio.sleep(.001)
        self.assertTrue(started.is_set())
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        # Refused before dispatch (nothing sent): not a denial and not an unknown outcome.
        with self.assertRaises(UnavailableBeforeDispatch):await transport.run(lambda:"should-not-queue")
        release.set()
        for _ in range(100):
            if finished.is_set():break
            await asyncio.sleep(.001)
        self.assertTrue(finished.is_set())
        self.assertEqual(await transport.run(lambda:"next"),"next")

    async def test_failed_thread_releases_capacity(self):
        transport=BoundedBlockingTransport(maximum=1)
        self.addCleanup(transport.close)
        def failed():raise ValueError("synthetic")
        with self.assertRaises(ValueError):await transport.run(failed)
        self.assertEqual(await transport.run(lambda:True),True)
