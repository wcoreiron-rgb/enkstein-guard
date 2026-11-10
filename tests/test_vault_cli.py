import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class VaultCLITests(unittest.TestCase):
    def test_lifecycle_and_failure_does_not_disclose_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)/'private-vault'
            def run(action):
                return subprocess.run([sys.executable, '-m', 'enkstein_guard', 'vault', action,
                                       '--directory', str(directory)], capture_output=True, text=True)
            for action in ('init', 'status', 'rotate', 'purge'):
                result = run(action)
                self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'], 'ok')
            self.assertEqual(run('init').returncode, 3)
            (directory/'keys/keyring.json').unlink()
            result = run('status')
            self.assertEqual(result.returncode, 3)
            self.assertNotIn(str(directory), result.stdout+result.stderr)
