"""Bound blocking HTTP work even when its awaiting coroutine is cancelled."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
from .runtime import UnavailableBeforeDispatch


class BoundedBlockingTransport:
    def __init__(self, maximum=16):
        if type(maximum) is not int or not 1<=maximum<=64:
            raise ValueError("invalid_transport_limit")
        self._slots=threading.BoundedSemaphore(maximum)
        self._executor=ThreadPoolExecutor(max_workers=maximum,thread_name_prefix="guard-http")

    async def run(self, function, *args):
        if not self._slots.acquire(blocking=False):
            # All worker slots are busy: nothing was sent, so this is neither a
            # denial nor an unknown outcome.
            raise UnavailableBeforeDispatch("connector_busy")
        def invoke():
            try:return function(*args)
            finally:self._slots.release()
        try:
            future=asyncio.get_running_loop().run_in_executor(self._executor,invoke)
        except BaseException:
            self._slots.release()
            raise
        # Consume a late exception after caller cancellation. Shield preserves
        # the future until actual completion; cancellation never releases a slot.
        future.add_done_callback(lambda f: f.exception() if not f.cancelled() else None)
        return await asyncio.shield(future)

    def close(self):
        self._executor.shutdown(wait=False,cancel_futures=False)
