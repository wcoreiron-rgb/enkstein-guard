import copy
from pathlib import Path
import tempfile
import unittest
from cryptography.exceptions import InvalidSignature
from enkstein_guard.release import create_signing_key, sign_artifacts, verify_artifacts


class ReleaseTests(unittest.TestCase):
    def test_signature_detects_artifact_or_manifest_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            public=create_signing_key(root/"key")
            artifact=root/"product.whl"
            artifact.write_bytes(b"fixture wheel")
            signed=sign_artifacts(root/"key",[artifact])
            self.assertTrue(verify_artifacts(signed,public,root))
            changed=copy.deepcopy(signed)
            changed["payload"]["artifacts"][0]["sha256"]="0"*64
            with self.assertRaises(InvalidSignature):
                verify_artifacts(changed,public,root)
            artifact.write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                verify_artifacts(signed,public,root)

    def test_wrong_trust_anchor_and_key_overwrite_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            create_signing_key(root/"key")
            other=create_signing_key(root/"other")
            artifact=root/"product.whl"
            artifact.write_bytes(b"fixture")
            signed=sign_artifacts(root/"key",[artifact])
            with self.assertRaises(InvalidSignature):
                verify_artifacts(signed,other,root)
            with self.assertRaises(FileExistsError):
                create_signing_key(root/"key")
