"""Egress allowlist proxy: policy, bypass attempts, TLS tunnel and kernel isolation."""
import asyncio
import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest

from enkstein_guard.contracts import SecurityContext
from enkstein_guard.egress import EgressClient, EgressDenied, EgressPolicy, EgressProxy, normalize_host
from enkstein_guard.identities import SecretBroker, SecretStore
from enkstein_guard.providers import BrokeredChatProvider
from enkstein_guard.runtime import AccessDenied, Operation, UnavailableBeforeDispatch

RESOLUTION = {"api.example.test": ["127.0.0.1"], "metadata.example.test": ["169.254.169.254"],
              "rebind.example.test": ["127.0.0.1"], "mixed.example.test": ["127.0.0.1", "10.0.0.5"]}
API_KEY = "synthetic-egress-test-api-key-value"


def make_certificate(directory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.example.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName("api.example.test")]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(key, hashes.SHA256()))
    cert, private = directory / "cert.pem", directory / "key.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return cert, private


class EgressTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="eg-egress-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "egress").mkdir(mode=0o700)
        self.socket = self.root / "egress" / "egress.sock"
        self.cert, key = make_certificate(self.root)
        self.captured = []
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.cert, key)
        self.tls_server = await asyncio.start_server(self.chat_upstream, "127.0.0.1", 0, ssl=context)
        self.echo_server = await asyncio.start_server(self.echo_upstream, "127.0.0.1", 0)
        self.linger_server = await asyncio.start_server(self.lingering_upstream, "127.0.0.1", 0)
        self.linger_port = self.linger_server.sockets[0].getsockname()[1]
        self.tls_port = self.tls_server.sockets[0].getsockname()[1]
        self.echo_port = self.echo_server.sockets[0].getsockname()[1]
        self.log = []
        policy = EgressPolicy.from_config([
            {"host": "api.example.test", "port": 443, "addresses": ["127.0.0.1/32"]},
            {"host": "api.example.test", "port": 7000, "addresses": ["127.0.0.1/32"]},
            {"host": "api.example.test", "port": 7001, "addresses": ["127.0.0.1/32"]},
            {"host": "metadata.example.test", "port": 443},
            {"host": "rebind.example.test", "port": 443},
            {"host": "mixed.example.test", "port": 443, "addresses": ["127.0.0.1/32"]},
        ])

        async def resolver(host, port):
            return RESOLUTION.get(host, [])

        async def open_connection(address, port):
            # Map the logical service ports onto the local fixture servers.
            return await asyncio.open_connection(address, {443: self.tls_port, 7000: self.echo_port,
                                                           7001: self.linger_port}.get(port, 1))

        self.proxy = await EgressProxy(policy, self.socket, resolver=resolver, open_connection=open_connection,
                                       header_timeout=0.5, max_connections=4, log=self.log.append).start()
        self.addAsyncCleanup(self.cleanup)
        self.client = EgressClient(self.socket, timeout=5)

    async def cleanup(self):
        await self.proxy.close()
        for server in (self.tls_server, self.echo_server, self.linger_server):
            server.close()
            await server.wait_closed()

    async def lingering_upstream(self, reader, writer):
        # Answers, then keeps its side open (like a server waiting for a TLS
        # close_notify that never comes).
        await reader.read(1024)
        writer.write(b"reply")
        await writer.drain()
        await asyncio.sleep(3)
        writer.close()

    async def test_tunnel_released_when_guard_closes_even_if_destination_lingers(self):
        def run():
            sock = self.client.connect("api.example.test", 7001)
            sock.sendall(b"request")
            data = sock.recv(100)
            sock.close()
            return data
        self.assertEqual(await self.blocking(run), b"reply")
        for _ in range(40):
            if self.proxy._active == 0:
                break
            await asyncio.sleep(0.05)
        self.assertEqual(self.proxy._active, 0)  # the proxy slot is free within the grace period

    async def echo_upstream(self, reader, writer):
        data = await reader.read(1024)
        writer.write(b"echo:" + data)
        await writer.drain()
        writer.close()

    async def chat_upstream(self, reader, writer):
        head = await reader.readuntil(b"\r\n\r\n")
        headers = dict(line.split(": ", 1) for line in head.decode().split("\r\n")[1:] if ": " in line)
        body = await reader.readexactly(int(headers.get("Content-Length", "0")))
        self.captured.append({"line": head.split(b"\r\n")[0].decode(), "headers": headers, "body": json.loads(body)})
        response = json.dumps({"choices": [{"message": {"role": "assistant", "content": "synthetic answer"}}]}).encode()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
                     % len(response) + response)
        await writer.drain()
        writer.close()

    async def raw(self, data):
        reader, writer = await asyncio.open_unix_connection(str(self.socket))
        writer.write(data)
        await writer.drain()
        response = await reader.read(4096)
        writer.close()
        return response.split(b"\r\n", 1)[0]

    async def blocking(self, function, *args):
        return await asyncio.to_thread(function, *args)

    async def test_allowlisted_tunnel_works(self):
        def run():
            sock = self.client.connect("api.example.test", 7000)
            sock.sendall(b"ping")
            data = sock.recv(100)
            sock.close()
            return data
        self.assertEqual(await self.blocking(run), b"echo:ping")
        self.assertEqual(self.log[-1]["decision"], "allowed")

    async def test_bypass_attempts_denied(self):
        cases = [("evil.example.test", 443), ("api.example.test", 8443), ("127.0.0.1", 7000),
                 ("metadata.example.test", 443), ("rebind.example.test", 443), ("mixed.example.test", 443),
                 ("API.EXAMPLE.TEST.", 9999)]
        for host, port in cases:
            with self.subTest(host=host, port=port):
                with self.assertRaises(EgressDenied):
                    await self.blocking(self.client.connect, host, port)
        reasons = [entry["reason"] for entry in self.log if entry["decision"] == "denied"]
        self.assertIn("resolved_address_not_permitted", reasons)
        self.assertIn("destination_not_allowlisted", reasons)

    async def test_case_and_trailing_dot_normalized(self):
        self.assertEqual(normalize_host("API.Example.Test."), ("api.example.test", False))
        for bad in ("exa mple.test", "-bad.test", "a..b", "localhost", "x" * 254, "", "1.2.3"):
            with self.assertRaises(ValueError):
                normalize_host(bad)

    async def test_protocol_abuse_rejected(self):
        self.assertEqual(await self.raw(b"GET http://api.example.test/ HTTP/1.1\r\nHost: x\r\n\r\n"),
                         b"HTTP/1.1 405 Method Not Allowed")
        self.assertEqual(await self.raw(b"CONNECT api.example.test:7000 HTTP/1.0\r\n\r\n"), b"HTTP/1.1 400 Bad Request")
        self.assertEqual(await self.raw(b"CONNECT api.example.test:7000 HTTP/1.1\r\nbroken\r\n\r\n"),
                         b"HTTP/1.1 400 Bad Request")
        self.assertEqual(await self.raw(b"CONNECT api.example.test:7000 HTTP/1.1\r\n\r\nsmuggled"),
                         b"HTTP/1.1 400 Bad Request")
        self.assertEqual(await self.raw(b"CONNECT user@api.example.test:7000 HTTP/1.1\r\n\r\n"),
                         b"HTTP/1.1 400 Bad Request")
        self.assertEqual(await self.raw(b"CONNECT api.example.test:7000 HTTP/1.1\r\nX: " + b"a" * 9000 + b"\r\n\r\n"),
                         b"HTTP/1.1 400 Bad Request")
        self.assertEqual(await self.raw(b"CONNECT api.\xff.test:7000 HTTP/1.1\r\n\r\n"), b"HTTP/1.1 400 Bad Request")
        reader, writer = await asyncio.open_unix_connection(str(self.socket))
        writer.write(b"CONNECT api.example.test:7000 HTTP/1.1\r\n")
        await writer.drain()
        self.assertEqual((await reader.read(100)).split(b"\r\n")[0], b"HTTP/1.1 400 Bad Request")
        writer.close()
        self.assertTrue(await self.blocking(self.client.health))

    @unittest.skipUnless(sys.platform.startswith("linux"), "SO_PEERCRED")
    async def test_unlisted_peer_uid_rejected(self):
        other = self.root / "egress" / "peer.sock"
        proxy = await EgressProxy(self.proxy.policy, other, client_uids={os.getuid() + 1}).start()
        try:
            with self.assertRaises(EgressDenied):
                await self.blocking(EgressClient(other).connect, "api.example.test", 7000)
        finally:
            await proxy.close()

    async def test_end_to_end_tls_provider_through_tunnel(self):
        store_root = self.root / "secrets"
        store = SecretStore.initialize(store_root / "s/secrets.sqlite3", store_root / "k/secrets.key")
        store.set("hatz", API_KEY, tenant="tenant-a", destination="api.example.test", routes=["model.chat"])
        provider = BrokeredChatProvider(endpoint="https://api.example.test/v1/chat/completions",
                                        allowed_hosts={"api.example.test"}, model="synthetic-model",
                                        broker=SecretBroker(store), credential_name="hatz",
                                        authentication="x-api-key", egress=self.client,
                                        ssl_context=ssl.create_default_context(cafile=str(self.cert)))
        context = SecurityContext("tenant-a", "p", "a", "w", "o", "model.call", "v1")
        payload = json.dumps({"messages": [{"role": "user", "content": "hello"}]})
        operation = Operation(context, "model.chat", "synthetic-model", "api.example.test", payload, "digest")
        result = await provider.call(operation)
        self.assertEqual(result["choices"][0]["message"]["content"], "synthetic answer")
        headers = {key.lower(): value for key, value in self.captured[0]["headers"].items()}
        self.assertEqual(headers["x-api-key"], API_KEY)
        self.assertEqual(self.captured[0]["body"]["model"], "synthetic-model")
        self.assertNotIn(API_KEY, json.dumps(self.log))
        self.assertNotIn("hello", json.dumps(self.log))
        # Wrong trust anchor: TLS verification is never disabled. The fixture
        # server logs the rejected handshake; keep that expected noise quiet.
        asyncio.get_running_loop().set_exception_handler(lambda loop, context: None)
        untrusted = BrokeredChatProvider(endpoint="https://api.example.test/v1/chat/completions",
                                         allowed_hosts={"api.example.test"}, model="synthetic-model",
                                         broker=SecretBroker(store), credential_name="hatz",
                                         authentication="x-api-key", egress=self.client)
        # The handshake fails before any request byte is sent: refused before dispatch.
        with self.assertRaises(UnavailableBeforeDispatch) as caught:
            await untrusted.call(operation)
        self.assertEqual(str(caught.exception), "provider_tls_failed")
        self.assertEqual(len(self.captured), 1)

    @unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("unshare"), "Linux network namespaces")
    async def test_network_less_process_reaches_only_allowlisted_destination(self):
        probe = self.root / "probe.py"
        probe.write_text(
            "import json,socket,sys\n"
            "sys.path.insert(0, sys.argv[3])\n"
            "from enkstein_guard.egress import EgressClient, EgressDenied, network_interfaces\n"
            "result = {'interfaces': network_interfaces()}\n"
            "for name, target in (('direct_loopback', ('127.0.0.1', int(sys.argv[2]))), ('direct_internet', ('1.1.1.1', 443))):\n"
            "    try:\n"
            "        socket.create_connection(target, timeout=2).close(); result[name] = 'connected'\n"
            "    except OSError as error:\n"
            "        result[name] = 'blocked'\n"
            "try:\n"
            "    socket.getaddrinfo('example.com', 443); result['dns'] = 'resolved'\n"
            "except OSError:\n"
            "    result['dns'] = 'blocked'\n"
            "client = EgressClient(sys.argv[1])\n"
            "sock = client.connect('api.example.test', 7000); sock.sendall(b'ns'); result['tunnel'] = sock.recv(100).decode(); sock.close()\n"
            "try:\n"
            "    client.connect('evil.example.test', 443); result['denied_destination'] = 'connected'\n"
            "except EgressDenied:\n"
            "    result['denied_destination'] = 'blocked'\n"
            "print(json.dumps(result))\n")
        import enkstein_guard
        package_root = str(Path(enkstein_guard.__file__).resolve().parent.parent)
        process = await asyncio.create_subprocess_exec(
            "unshare", "-rn", sys.executable, "-I", str(probe), str(self.socket), str(self.echo_port), package_root,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 60)
        if process.returncode and b"Operation not permitted" in stderr:
            self.skipTest("user namespaces unavailable")
        result = json.loads(stdout)
        self.assertEqual(result["interfaces"], ["lo"])
        self.assertEqual((result["direct_loopback"], result["direct_internet"], result["dns"]),
                         ("blocked", "blocked", "blocked"))
        self.assertEqual(result["tunnel"], "echo:ns")
        self.assertEqual(result["denied_destination"], "blocked")
