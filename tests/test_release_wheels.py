"""Artifact admission and preservation regressions; no builds or downloads."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
SPEC = importlib.util.spec_from_file_location("guard_release_wheels", TOOLS / "release_wheels.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


class ReleaseArtifactBoundaryTests(unittest.TestCase):
    def test_default_does_not_require_or_resolve_optional_sdk(self):
        self.assertIsNone(release.optional_agt_wheel(None, Path("/nonexistent")))

    def test_tampered_same_name_sdk_cannot_enter_lock_or_replace_old_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / release.AGT_FILENAME
            path.write_bytes(b"unreviewed package with the expected filename")
            lock = root / "requirements.txt"
            lock.write_text("previous==1 --hash=sha256:kept\n")
            with self.assertRaisesRegex(ValueError, "unreviewed_agt_wheel"):
                release.optional_agt_wheel(path, root)
            self.assertEqual(lock.read_text(), "previous==1 --hash=sha256:kept\n")
            self.assertFalse((root / "dist").exists())

    def test_external_or_symlink_escape_is_rejected_before_package_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "project"
            root.mkdir()
            outside = base / release.AGT_FILENAME
            outside.write_bytes(b"outside")
            link = root / release.AGT_FILENAME
            link.symlink_to(outside)
            for path in (outside, link):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    release.optional_agt_wheel(path, root)

    def test_repeated_wheelhouse_refresh_preserves_each_prior_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vendor = root / "dist/vendor-linux-arm64"
            vendor.mkdir(parents=True)
            wheel = vendor / "prior.whl"
            wheel.write_bytes(b"old wheel")
            lock = root / "deployment/requirements.txt"
            lock.parent.mkdir()
            lock.write_bytes(b"old lock")
            first = release.preserve_wheelhouse(root, vendor, lock)
            wheel.write_bytes(b"new wheel")
            lock.write_bytes(b"new lock")
            second = release.preserve_wheelhouse(root, vendor, lock)
            self.assertNotEqual(first, second)
            self.assertEqual((first / wheel.relative_to(root)).read_bytes(), b"old wheel")
            self.assertEqual((first / lock.relative_to(root)).read_bytes(), b"old lock")
            self.assertEqual((second / wheel.relative_to(root)).read_bytes(), b"new wheel")
            self.assertEqual((second / lock.relative_to(root)).read_bytes(), b"new lock")
            self.assertEqual(wheel.read_bytes(), b"new wheel")


if __name__ == "__main__":
    unittest.main()
