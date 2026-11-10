"""Independent egress proxy and tunnelled HTTPS client for Guard connectors.

Production deployment: the Guard process has no network interfaces
(``network_mode: none``). Its connectors reach the network only by sending
``CONNECT host:port`` over a Unix socket to this proxy, which runs as a separate
process/UID with network access and its own read-only allowlist. The proxy
resolves names itself, requires every resolved address to be permitted
(globally routable unless the rule names explicit networks) and connects to
the address it checked. TLS is end to end between Guard and the destination;
the proxy never sees request bodies or credentials.

This is a destination allowlist, not content inspection, DLP or a cloud
firewall. It does not constrain processes outside this topology.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import functools
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys
import time
import urllib.request

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class EgressDenied(Exception):
    """Fixed reason codes only."""


class ConnectFailed(Exception):
    """The tunnel or TLS session could not be established, so no request byte
    reached the destination. ``code`` is a fixed reason code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def normalize_host(host):
    if not isinstance(host, str) or not host or len(host) > 253 or host != host.strip():
        raise ValueError("invalid_host")
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    try:
        address = ipaddress.ip_address(host)
        return str(address), True
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels) or labels[-1].isdigit():
        raise ValueError("invalid_host")
    return host, False


@dataclass(frozen=True)
class EgressRule:
    host: str
    port: int
    networks: tuple = ()

    @classmethod
    def from_dict(cls, data):
        if type(data) is not dict or set(data) - {"host", "port", "addresses"} or not {"host", "port"} <= set(data):
            raise ValueError("invalid_egress_rule")
        host, _ = normalize_host(data["host"])
        if type(data["port"]) is not int or not 1 <= data["port"] <= 65535:
            raise ValueError("invalid_egress_port")
        networks = data.get("addresses", [])
        if type(networks) is not list or len(networks) > 32:
            raise ValueError("invalid_egress_addresses")
        try:
            parsed = tuple(ipaddress.ip_network(item, strict=True) for item in networks)
        except (TypeError, ValueError):
            raise ValueError("invalid_egress_addresses") from None
        return cls(host, data["port"], parsed)


class EgressPolicy:
    def __init__(self, rules):
        self.rules = tuple(rules)
        keys = [(rule.host, rule.port) for rule in self.rules]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate_egress_rule")

    @classmethod
    def from_config(cls, allow):
        if type(allow) is not list or len(allow) > 256:
            raise ValueError("invalid_egress_allowlist")
        return cls(EgressRule.from_dict(item) for item in allow)

    def match(self, host, port):
        for rule in self.rules:
            if rule.host == host and rule.port == port:
                return rule
        return None

    @staticmethod
    def permitted(rule, address):
        address = ipaddress.ip_address(address)
        if rule.networks:
            return any(address in network for network in rule.networks)
        return address.is_global and not address.is_multicast and not address.is_reserved


def _peer_uid(sock):
    if not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"):
        return None
    _, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return uid


async def _default_resolver(host, port):
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen = []
    for family, _, _, _, address in infos:
        if family in (socket.AF_INET, socket.AF_INET6) and address[0] not in seen:
            seen.append(address[0])
    return seen


class EgressProxy:
    def __init__(self, policy: EgressPolicy, socket_path, *, client_uids=None, socket_group=None, resolver=None,
                 connect_timeout=10, idle_timeout=60, header_timeout=5, max_connections=64,
                 max_header_bytes=8192, max_tunnel_bytes=67_108_864, log=None, open_connection=None,
                 client_close_grace=0.25):
        """``resolver`` and ``open_connection`` are injectable for tests; the
        proxy always connects to an address it has itself validated."""
        if client_uids is not None and (not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED")):
            raise ValueError("linux_peer_credentials_required")
        self._open = open_connection or asyncio.open_connection
        self.policy = policy
        self.path = Path(socket_path)
        self.client_uids = frozenset(client_uids) if client_uids is not None else None
        self.socket_group = socket_group
        self.resolver = resolver or _default_resolver
        self.connect_timeout, self.idle_timeout, self.header_timeout = connect_timeout, idle_timeout, header_timeout
        self.max_connections, self.max_header_bytes, self.max_tunnel_bytes = max_connections, max_header_bytes, max_tunnel_bytes
        self.client_close_grace = client_close_grace
        self.log = log or (lambda event: None)
        self._server = None
        self._active = 0
        self._tasks = set()
        self.counters = {"allowed": 0, "denied": 0, "failed": 0, "health": 0}

    async def start(self):
        parent = self.path.parent
        info = parent.stat()
        expected = 0o710 if self.socket_group is not None else 0o700
        if (parent.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != expected
                or (self.socket_group is not None and info.st_gid != self.socket_group)):
            raise ValueError("private_egress_directory_required")
        if self.path.exists() or self.path.is_symlink():
            raise ValueError("egress_socket_exists")
        self._server = await asyncio.start_unix_server(self._handle, path=str(self.path),
                                                       limit=self.max_header_bytes + 1)
        if self.socket_group is not None:
            os.chown(self.path, -1, self.socket_group)
        self.path.chmod(0o660 if self.socket_group is not None else 0o600)
        info = self.path.stat()
        self._identity = (info.st_dev, info.st_ino)
        return self

    async def close(self):
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        for task in tuple(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._server = None
        try:
            info = self.path.lstat()
            if (info.st_dev, info.st_ino) == self._identity and stat.S_ISSOCK(info.st_mode):
                self.path.unlink()
        except FileNotFoundError:
            pass

    def _decide(self, decision, reason, host=None, port=None, uid=None):
        self.counters[decision] = self.counters.get(decision, 0) + 1
        try:
            self.log({"event": "egress", "decision": decision, "reason": reason, "destination": host,
                      "port": port, "uid": uid, "time": int(time.time())})
        except Exception:
            pass

    @staticmethod
    async def _reply(writer, status, reason):
        writer.write(("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" % (status, reason)).encode())
        try:
            await asyncio.wait_for(writer.drain(), 2)
        except (ConnectionError, TimeoutError):
            pass

    async def _head(self, reader):
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = await reader.read(1024)
            if not chunk:
                raise EgressDenied("incomplete_request")
            data.extend(chunk)
            if len(data) > self.max_header_bytes:
                raise EgressDenied("request_header_too_large")
        head, _, rest = bytes(data).partition(b"\r\n\r\n")
        if rest:
            raise EgressDenied("unexpected_request_body")
        try:
            lines = head.decode("ascii").split("\r\n")
        except UnicodeDecodeError:
            raise EgressDenied("non_ascii_request") from None
        for line in lines[1:]:
            if ":" not in line or line[0] in " \t":
                raise EgressDenied("malformed_header")
        return lines[0]

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        self._tasks.add(task)
        uid = host = port = None
        upstream = None
        try:
            sock = writer.get_extra_info("socket")
            uid = _peer_uid(sock) if self.client_uids is not None else None
            if self.client_uids is not None and uid not in self.client_uids:
                self._decide("denied", "peer_not_permitted", uid=uid)
                await self._reply(writer, 403, "Forbidden")
                return
            if self._active >= self.max_connections:
                self._decide("denied", "proxy_busy", uid=uid)
                await self._reply(writer, 503, "Busy")
                return
            self._active += 1
            try:
                try:
                    line = await asyncio.wait_for(self._head(reader), self.header_timeout)
                except TimeoutError:
                    raise EgressDenied("request_header_timeout") from None
                parts = line.split(" ")
                if len(parts) != 3 or parts[2] != "HTTP/1.1":
                    raise EgressDenied("malformed_request_line")
                method, target, _ = parts
                if method == "HEAD" and target == "/egress-health":
                    self.counters["health"] += 1
                    await self._reply(writer, 204, "No Content")
                    return
                if method != "CONNECT":
                    self._decide("denied", "method_not_allowed", uid=uid)
                    await self._reply(writer, 405, "Method Not Allowed")
                    return
                match = re.fullmatch(r"(\[[0-9a-fA-F:.]+\]|[^:\[\]]+):([0-9]{1,5})", target)
                if match is None:
                    raise EgressDenied("malformed_target")
                raw_host = match[1].strip("[]")
                port = int(match[2])
                try:
                    host, literal = normalize_host(raw_host)
                except ValueError:
                    raise EgressDenied("invalid_host") from None
                rule = self.policy.match(host, port)
                if rule is None:
                    self._decide("denied", "destination_not_allowlisted", host, port, uid)
                    await self._reply(writer, 403, "Forbidden")
                    return
                try:
                    addresses = [host] if literal else await asyncio.wait_for(self.resolver(host, port),
                                                                              self.connect_timeout)
                except Exception:
                    self._decide("failed", "resolution_failed", host, port, uid)
                    await self._reply(writer, 502, "Bad Gateway")
                    return
                if not addresses or any(not self.policy.permitted(rule, address) for address in addresses):
                    self._decide("denied", "resolved_address_not_permitted", host, port, uid)
                    await self._reply(writer, 403, "Forbidden")
                    return
                for address in addresses:
                    try:
                        upstream = await asyncio.wait_for(self._open(address, port), self.connect_timeout)
                        break
                    except (OSError, TimeoutError):
                        upstream = None
                if upstream is None:
                    self._decide("failed", "upstream_unreachable", host, port, uid)
                    await self._reply(writer, 502, "Bad Gateway")
                    return
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
                self._decide("allowed", "allowlisted", host, port, uid)
                await self._relay(reader, writer, *upstream)
            finally:
                self._active -= 1
        except EgressDenied as error:
            self._decide("denied", str(error), host, port, uid)
            await self._reply(writer, 400, "Bad Request")
        except (ConnectionError, TimeoutError, asyncio.IncompleteReadError):
            pass
        finally:
            if upstream is not None:
                upstream[1].close()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self._tasks.discard(task)

    async def _relay(self, client_reader, client_writer, upstream_reader, upstream_writer):
        transferred = 0

        async def pipe(source, sink):
            nonlocal transferred
            while True:
                data = await asyncio.wait_for(source.read(65536), self.idle_timeout)
                if not data:
                    break
                transferred += len(data)
                if transferred > self.max_tunnel_bytes:
                    break
                sink.write(data)
                await sink.drain()
            try:
                sink.write_eof()
            except (OSError, RuntimeError, AttributeError):
                pass

        outbound = asyncio.create_task(pipe(client_reader, upstream_writer))
        inbound = asyncio.create_task(pipe(upstream_reader, client_writer))
        tasks = [outbound, inbound]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if outbound in done and pending:
                # Guard closed its end: nothing more can be delivered to it, so a
                # destination that delays its own close (for example waiting for
                # a TLS close_notify) must not hold a proxy slot.
                await asyncio.wait(pending, timeout=self.client_close_grace)
            elif pending:
                await asyncio.wait(pending)  # bounded by the idle timeout in pipe()
        finally:
            for item in tasks:
                item.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


# -- Guard-side client ---------------------------------------------------------
class EgressClient:
    """Blocking tunnel client used from bounded connector worker threads."""

    def __init__(self, socket_path, *, timeout=10):
        self.path = str(socket_path)
        self.timeout = timeout

    def _exchange(self, request):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
            sock.sendall(request)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(1024)
                if not chunk:
                    raise EgressDenied("egress_disconnected")
                data += chunk
                if len(data) > 8192:
                    raise EgressDenied("egress_response_invalid")
            head, _, rest = data.partition(b"\r\n\r\n")
            status = head.split(b"\r\n", 1)[0].split(b" ")
            if len(status) < 2 or status[0] != b"HTTP/1.1" or rest:
                raise EgressDenied("egress_response_invalid")
            return sock, int(status[1])
        except EgressDenied:
            sock.close()
            raise
        except Exception:
            sock.close()
            raise EgressDenied("egress_unavailable") from None

    def connect(self, host, port, timeout=None):
        host, literal = normalize_host(host)
        target = "[%s]:%d" % (host, port) if literal and ":" in host else "%s:%d" % (host, port)
        sock, status = self._exchange(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode())
        if status != 200:
            sock.close()
            raise EgressDenied("egress_denied_%d" % status)
        sock.settimeout(timeout if timeout is not None else self.timeout)
        return sock

    def health(self):
        sock, status = self._exchange(b"HEAD /egress-health HTTP/1.1\r\nHost: guard\r\n\r\n")
        sock.close()
        return status == 204

    def https_handler(self, context=None):
        return _EgressHTTPSHandler(self, context)


class _TunnelHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, *, egress, **kwargs):
        super().__init__(host, **kwargs)
        self._egress = egress

    def connect(self):
        # Failures here happen before any request byte is sent.
        try:
            sock = self._egress.connect(self.host, self.port or 443, self.timeout)
        except EgressDenied as error:
            raise ConnectFailed(str(error) if str(error).startswith("egress_") else "egress_failed") from None
        except Exception:
            raise ConnectFailed("egress_unavailable") from None
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception as error:
            sock.close()
            import ssl
            raise ConnectFailed("provider_tls_failed" if isinstance(error, ssl.SSLError)
                                else "provider_connection_failed") from None


class _EgressHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, egress, context=None):
        super().__init__(context=context)
        self._egress_client = egress
        self._egress_context = context

    def https_open(self, req):
        return self.do_open(functools.partial(_TunnelHTTPSConnection, egress=self._egress_client), req,
                            context=self._egress_context)


def opener(egress=None, context=None):
    """urllib opener without environment proxies or redirects; tunnelled when
    ``egress`` is supplied, direct (development only) otherwise."""
    from .providers import _NoRedirect
    https = egress.https_handler(context) if egress is not None else urllib.request.HTTPSHandler(context=context)
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), https, _NoRedirect())


def network_interfaces():
    """Interface names in this process's network namespace, or None.

    if_nameindex() queries the current namespace; /sys/class/net can show a
    different namespace when sysfs was not remounted, so it is only a fallback.
    """
    try:
        return sorted(name for _, name in socket.if_nameindex())
    except OSError:
        try:
            return sorted(os.listdir("/sys/class/net"))
        except OSError:
            return None
