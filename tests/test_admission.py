import hashlib
from pathlib import Path
import tempfile
import unittest

from enkstein_guard.admission import scan_python, undeclared
from enkstein_guard.orchestration import Admission
from enkstein_guard.runtime import AccessDenied


class CapabilityScanTests(unittest.TestCase):
    def test_detects_common_capabilities(self):
        cases = {
            b"import socket\n": {"network"},
            b"from urllib.request import urlopen\n": {"network"},
            b"import subprocess\nsubprocess.run(['ls'])\n": {"process"},
            b"import os\nos.system('id')\n": {"process"},
            b"import os\nprint(os.environ['HOME'])\n": {"environment"},
            b"open('x', 'w').write('y')\n": {"filesystem_write"},
            b"import ctypes\n": {"native"},
            b"eval('1+1')\n": {"dynamic_code"},
            b"getattr(__builtins__, 'ev' + 'al')('1')\n": {"dynamic_code"},
            b"import importlib\nimportlib.import_module('so' + 'cket')\n": {"dynamic_code"},
            b"def handler(payload):\n    return {'ok': payload.get('x')}\n": set(),
            b"open('x').read()\n": set(),
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(set(scan_python(source)), expected)
        self.assertEqual(scan_python(b"def (:\n"), frozenset({"unparseable"}))

    def test_known_miss_is_explicit(self):
        # Behaviour reached only through an allowed, already-imported object is
        # not modelled; runtime containment remains the enforcing control.
        source = b"import json\nloader = json.loads\nloader('{}')\n"
        self.assertEqual(set(scan_python(source)), set())
        with self.assertRaises(ValueError):
            undeclared(source, {"teleport"})

    def test_admission_denies_undeclared_capability(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "tool.py"
            path.write_bytes(b"import socket\ndef run(payload):\n    return {}\n")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(AccessDenied):
                Admission(str(path), digest, frozenset()).verify()
            Admission(str(path), digest, frozenset({"network"})).verify()
            Admission(str(path), digest).verify()  # Legacy: hash pin only.
