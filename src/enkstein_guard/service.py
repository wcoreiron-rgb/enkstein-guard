"""Bounded local IPC boundary. Trusted connectors stay in the service process.

Requires Unix sockets and a private operator-owned directory. Deploy agents with
restricted credentials and egress separately; this service is not a firewall.
"""
import asyncio
import json
import os
from pathlib import Path
import stat
import socket
import struct
import sys
from types import MappingProxyType
from collections.abc import Mapping

from .runtime import AccessDenied, GuardError, UnavailableBeforeDispatch
from .outcomes import OutcomeError


class RequestReadTimeout(Exception):
    pass


class GuardService:
    # Accepted request shapes; subclasses may extend (e.g. approval tickets).
    _request_shapes = ({"credential", "route", "payload"}, {"credential", "route", "payload", "request_id"})

    def __init__(self, runtime, socket_path, *, max_connections=32,
                 max_frame_bytes=1_048_576, request_timeout=60, outcomes=None, read_timeout=2,
                 peer_bindings=None, per_peer_connections=4, socket_group=None):
        if type(max_connections) is not int or not 1 <= max_connections <= 1024:
            raise ValueError("invalid_connection_limit")
        if type(max_frame_bytes) is not int or not 1024 <= max_frame_bytes <= 16_777_216:
            raise ValueError("invalid_frame_limit")
        if type(request_timeout) not in (int, float) or not 0 < request_timeout <= 300:
            raise ValueError("invalid_request_timeout")
        if type(read_timeout) not in (int,float) or not 0 < read_timeout <= 10:
            raise ValueError("invalid_read_timeout")
        if (type(per_peer_connections) is not int or not 1 <= per_peer_connections <= 1024
                or (peer_bindings is not None and per_peer_connections > max_connections)):
            raise ValueError("invalid_peer_connection_limit")
        bindings = {}
        if peer_bindings is not None:
            if not isinstance(peer_bindings,Mapping):
                raise ValueError("invalid_peer_bindings")
            if not sys.platform.startswith("linux") or not hasattr(socket,"SO_PEERCRED"):
                raise ValueError("linux_peer_credentials_required")
            for uid, identity in peer_bindings.items():
                if (type(uid) is not int or uid <= 0 or uid == os.getuid()
                        or type(identity) not in (tuple,list) or len(identity) != 3
                        or any(not isinstance(v,str) or not v or len(v)>256 for v in identity)):
                    raise ValueError("invalid_peer_binding")
                bindings[uid] = tuple(identity)
            if not bindings or len(bindings)*per_peer_connections > max_connections:
                raise ValueError("peer_reservations_exceed_capacity")
        if socket_group is not None:
            if not bindings or type(socket_group) is not int or socket_group not in {os.getgid(),*os.getgroups()}:
                raise ValueError("invalid_socket_group")
        self._peer_bindings = MappingProxyType(bindings)
        self._peer_active = {}
        self._peer_limit = per_peer_connections
        self._socket_group = socket_group
        self.read_timeout = read_timeout
        self.runtime = runtime
        self.outcomes = outcomes
        self.path = Path(socket_path)
        self.limit = max_frame_bytes
        self.timeout = request_timeout
        self.maximum = max_connections
        self._active = 0
        self._discarding = 0
        self._tasks = set()
        self._server = None
        self._identity = None
        # Admission counters for operator status; no identities or payloads.
        self.counters = {"admitted": 0, "busy": 0, "peer_denied": 0, "read_timeout": 0, "invalid": 0}

    # Hooks for trusted subclasses; the base service keeps its response shape.
    def _begin_connection(self):
        return None

    def _finalize(self, response):
        return response

    def _valid_request(self, request):
        return (type(request) is dict and set(request) in self._request_shapes
                and isinstance(request["credential"], str)
                and isinstance(request["route"], str) and type(request["payload"]) is dict)

    @property
    def outcomes(self):
        return self._outcomes

    @outcomes.setter
    def outcomes(self, ledger):
        if ledger is not None:
            ledger.configure_tenants(self.runtime.registered_tenants())
        self._outcomes = ledger

    async def start(self):
        if self._server is not None:
            raise ValueError("service_already_started")
        if os.name != "posix" or not hasattr(asyncio, "start_unix_server"):
            raise ValueError("unix_socket_required")
        parent = self.path.parent
        info = parent.stat()
        expected_mode = 0o710 if self._socket_group is not None else 0o700
        if (parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != expected_mode
                or (self._socket_group is not None and info.st_gid != self._socket_group)):
            raise ValueError("private_service_directory_required")
        if self.path.exists() or self.path.is_symlink():
            raise ValueError("socket_path_exists")
        self._server = await asyncio.start_unix_server(self._handle, path=self.path, limit=self.limit + 1)
        if self._socket_group is not None:
            os.chown(self.path,-1,self._socket_group)
        self.path.chmod(0o660 if self._socket_group is not None else 0o600)
        info = self.path.stat()
        self._identity = (info.st_dev, info.st_ino)
        return self

    async def close(self):
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        # Cancellation may follow an external side effect. Clients must not
        # interpret disconnects as proof that an action did not execute.
        tasks = tuple(self._tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._server = None
        try:
            info = self.path.lstat()
            if (info.st_dev, info.st_ino) == self._identity and stat.S_ISSOCK(info.st_mode):
                self.path.unlink()
        except FileNotFoundError:
            pass

    def _finish(self, name, state):
        try:
            self.outcomes.finish(name, state)
        except Exception:
            raise GuardError("request_tracking_failed_outcome_unknown") from None

    async def _execute(self, request):
        name = None
        if self.outcomes is not None:
            try:
                principal = self.runtime.authorize(request["credential"], request["route"])
                name, state = self.outcomes.begin(principal, request.get("request_id"), request["route"], request["payload"])
            except OutcomeError:
                return {"status": "request_tracking_unavailable_or_conflict"}
            if state != "new":
                return {"status": {"executing": "in_progress", "completed": "completed_no_replay",
                                   "denied": "denied", "uncertain": "outcome_unknown_no_replay"}[state]}
        elif "request_id" in request:
            return {"status": "durable_request_tracking_unavailable"}
        try:
            result = await self.runtime.execute(request["credential"], request["route"], request["payload"])
        except UnavailableBeforeDispatch as error:
            # Nothing was dispatched: free the ID for a later attempt.
            if name is not None:
                try:
                    self.outcomes.abandon(name)
                except Exception:
                    pass
            return {"status": "unavailable_no_execution", "reason": str(error)}
        except AccessDenied:
            if name is not None:
                try:
                    self.outcomes.finish(name, "denied")
                except Exception:
                    pass  # still a denial: nothing was dispatched
            raise
        except BaseException:
            if name is not None:
                self._finish(name, "uncertain")
            raise
        if name is not None:
            self._finish(name, "completed")
        return {"status": "ok", "result": result}

    def _peer_uid(self, writer):
        if not self._peer_bindings:
            return None
        try:
            peer = writer.get_extra_info("socket")
            _,uid,_ = struct.unpack("3i",peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")))
            if uid not in self._peer_bindings:
                raise ValueError()
            return uid
        except Exception:
            raise AccessDenied("peer_identity_forbidden") from None

    DISCARD_CONCURRENCY = 8

    async def _discard_input(self, reader, *, seconds=0.1):
        """Read and drop at most one frame for at most ``seconds``; beyond
        ``DISCARD_CONCURRENCY`` simultaneous refusals, close immediately so a
        flood of refused connections cannot hold memory or tasks."""
        if self._discarding >= self.DISCARD_CONCURRENCY:
            return
        self._discarding += 1
        remaining = min(self.limit + 1, 1_048_577)
        try:
            async with asyncio.timeout(seconds):
                while remaining > 0:
                    data = await reader.read(min(65536, remaining))
                    if not data:
                        break
                    remaining -= len(data)
        except (TimeoutError, ConnectionError, ValueError):
            pass
        finally:
            self._discarding -= 1

    def _bind_request(self, uid, request):
        if self._peer_bindings:
            principal = self.runtime.authorize(request["credential"],request["route"])
            identity = (principal.tenant_id,principal.principal_id,principal.agent_id)
            if identity != self._peer_bindings[uid]:
                raise AccessDenied("peer_credential_mismatch")

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        self._tasks.add(task)
        self._begin_connection()
        uid = None
        permitted = True
        try:
            uid = self._peer_uid(writer)
        except AccessDenied:
            permitted = False
            self.counters["peer_denied"] += 1
        admitted = permitted and self._active < self.maximum and (not self._peer_bindings or self._peer_active.get(uid,0) < self._peer_limit)
        if admitted:
            self._active += 1
            self.counters["admitted"] += 1
            if self._peer_bindings:
                self._peer_active[uid] = self._peer_active.get(uid,0)+1
        elif permitted:
            self.counters["busy"] += 1
        response = {"status": "busy" if permitted else "denied"}
        consumed = False
        try:
            if admitted:
                try:
                    async with asyncio.timeout(self.timeout):
                        try:
                            frame = await asyncio.wait_for(reader.readline(), self.read_timeout)
                        except TimeoutError:
                            raise RequestReadTimeout() from None
                        if not frame.endswith(b"\n") or len(frame) > self.limit:
                            raise ValueError()
                        consumed = True
                        request = json.loads(frame, object_pairs_hook=_unique)
                        if not self._valid_request(request):
                            raise ValueError()
                        self._bind_request(uid,request)
                        response = await self._execute(request)
                except RequestReadTimeout:
                    self.counters["read_timeout"] += 1
                    response = {"status": "request_read_timeout_no_execution"}
                except AccessDenied:
                    response = {"status": "denied"}
                except UnavailableBeforeDispatch as error:
                    response = {"status": "unavailable_no_execution", "reason": str(error)}
                except GuardError:
                    response = {"status": "execution_or_audit_failed_outcome_unknown"}
                except TimeoutError:
                    response = {"status": "timeout_outcome_unknown"}
                except Exception:
                    self.counters["invalid"] += 1
                    response = {"status": "invalid_request_or_response"}
            try:
                response = self._finalize(response)
                encoded = json.dumps(response, allow_nan=False, separators=(",", ":")).encode() + b"\n"
                if len(encoded) > self.limit:
                    raise ValueError()
            except Exception:
                encoded = b'{"status":"response_unavailable_outcome_unknown"}\n'
            writer.write(encoded)
            await asyncio.wait_for(writer.drain(), 2)
            if not consumed:
                # Closing a Unix socket with unread request bytes resets the
                # peer before it reads the answer; a refused client must see
                # "busy"/"denied" (safe to retry), not a reset that it would
                # have to treat as an unknown outcome. Bounded in time and size.
                await self._discard_input(reader)
        except (ConnectionError, TimeoutError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            if admitted:
                self._active -= 1
                if self._peer_bindings:
                    self._peer_active[uid] -= 1
            self._tasks.discard(task)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_field")
        result[key] = value
    return result


async def guarded_request(socket_path, credential, route, payload, *, timeout=65, max_frame_bytes=1_048_576, request_id=None,
                          approval=None):
    """One attempt only. A disconnect/timeout never triggers an automatic retry."""
    request = {"credential": credential, "route": route, "payload": payload}
    if request_id is not None:
        request["request_id"] = request_id
    if approval is not None:
        request["approval"] = approval
    frame = json.dumps(request, allow_nan=False).encode() + b"\n"
    if len(frame) > max_frame_bytes:
        raise ValueError("request_too_large")
    async with asyncio.timeout(timeout):
        reader, writer = await asyncio.open_unix_connection(str(socket_path), limit=max_frame_bytes + 1)
        try:
            writer.write(frame)
            try:
                await writer.drain()
            except (BrokenPipeError, ConnectionResetError):
                # The service may refuse a connection (busy, peer denied) and
                # close it before reading; its one-line answer is still readable.
                pass
            data = await reader.readline()
            if not data.endswith(b"\n") or len(data) > max_frame_bytes:
                raise GuardError("service_disconnected_outcome_unknown")
            return json.loads(data, object_pairs_hook=_unique)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
