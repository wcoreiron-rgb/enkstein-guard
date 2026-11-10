import os
import socket
import struct
import unittest
from unittest.mock import Mock,patch
from enkstein_guard.runtime import Principal,AccessDenied
from enkstein_guard.service import GuardService


class PeerBindingTests(unittest.TestCase):
    def setUp(self):
        self.runtime=Mock()
        self.runtime.authorize.return_value=Principal("a","user","agent",frozenset({"read"}))

    def service(self,**kwargs):
        with patch("enkstein_guard.service.sys.platform","linux"),patch.object(socket,"SO_PEERCRED",17,create=True):
            return GuardService(self.runtime,"/tmp/peer-fixture.sock",peer_bindings={11001:("a","user","agent")},**kwargs)

    def test_kernel_identity_must_match_registered_os_uid(self):
        service=self.service()
        writer=Mock()
        writer.get_extra_info.return_value.getsockopt.return_value=struct.pack("3i",0,11001,10001)
        with patch.object(socket,"SO_PEERCRED",17,create=True):
            self.assertEqual(service._peer_uid(writer),11001)
            writer.get_extra_info.return_value.getsockopt.return_value=struct.pack("3i",0,11002,10001)
            with self.assertRaises(AccessDenied):service._peer_uid(writer)

    def test_stolen_other_agents_credential_rejected(self):
        service=self.service()
        service._bind_request(11001,{"credential":"fixture","route":"read"})
        self.runtime.authorize.return_value=Principal("b","other","other-agent",frozenset({"read"}))
        with self.assertRaises(AccessDenied):service._bind_request(11001,{"credential":"stolen","route":"read"})

    def test_bindings_are_snapshotted(self):
        identities={11001:["a","user","agent"]}
        with patch("enkstein_guard.service.sys.platform","linux"),patch.object(socket,"SO_PEERCRED",17,create=True):
            service=GuardService(self.runtime,"/tmp/peer-fixture.sock",peer_bindings=identities)
        identities[11001][0]="b"
        identities[11002]=["b","other","other-agent"]
        self.assertEqual(service._peer_bindings[11001],("a","user","agent"))
        self.assertNotIn(11002,service._peer_bindings)

    def test_capacity_must_reserve_all_peers_and_host_uid_is_forbidden(self):
        with self.assertRaises(ValueError):self.service(max_connections=2,per_peer_connections=4)
        with patch("enkstein_guard.service.sys.platform","linux"),patch.object(socket,"SO_PEERCRED",17,create=True):
            with self.assertRaises(ValueError):
                GuardService(self.runtime,"/tmp/peer-fixture.sock",peer_bindings={os.getuid():("a","user","agent")})

    def test_no_silent_platform_fallback(self):
        with patch("enkstein_guard.service.sys.platform","darwin"):
            with self.assertRaisesRegex(ValueError,"linux_peer_credentials_required"):
                GuardService(self.runtime,"/tmp/peer-fixture.sock",peer_bindings={11001:("a","user","agent")})
