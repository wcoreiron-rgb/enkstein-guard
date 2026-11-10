"""Pinned optional deployment artifact admission and wheelhouse preservation.

No SDK is imported here. The optional AGT wheel is a local build of the reviewed
public commit, not a floating package-index resolution. Provenance and the two
matching fixed-epoch builds are retained with the development evidence.
"""
import email
import hashlib
from pathlib import Path
import shutil
import uuid
import zipfile


AGT_NAME = "agent-governance-toolkit-control-plane"
AGT_VERSION = "5.0.0"
AGT_FILENAME = "agent_governance_toolkit_control_plane-5.0.0-py3-none-any.whl"
AGT_SHA256 = "e1c49dd3e407ae2e8e3267c4bc5b77d065c196a6553f85e99fc9d1a179f161dd"
AGT_SOURCE_COMMIT = "86db4607dcb67e5dbe48b885bc535f77be5e244d"
AGT_SOURCE_SHA256 = "d188680c60a6d6be25799fa8b0236e869c45c0a978650b9aabba254bd646492c"


def optional_agt_wheel(path: Path | None, root: Path) -> Path | None:
    """Admit only the exact reviewed pure wheel, before any build mutation."""
    if path is None:
        return None
    path = path.resolve(strict=True)
    path.relative_to(root.resolve(strict=True))
    if (not path.is_file() or path.name != AGT_FILENAME
            or hashlib.sha256(path.read_bytes()).hexdigest() != AGT_SHA256):
        raise ValueError("unreviewed_agt_wheel")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        wheel_names = [name for name in names if name.endswith(".dist-info/WHEEL")]
        if len(metadata_names) != 1 or len(wheel_names) != 1:
            raise ValueError("invalid_agt_wheel_metadata")
        metadata = email.message_from_bytes(archive.read(metadata_names[0]))
        wheel = email.message_from_bytes(archive.read(wheel_names[0]))
    if (metadata["Name"] != AGT_NAME or metadata["Version"] != AGT_VERSION
            or wheel.get_all("Tag") != ["py3-none-any"]
            or wheel["Root-Is-Purelib"] != "true"
            or any("extra ==" not in requirement
                   for requirement in metadata.get_all("Requires-Dist", []))):
        raise ValueError("unsupported_agt_wheel_contract")
    return path


def preserve_wheelhouse(root: Path, vendor: Path, *locks: Path) -> Path | None:
    """Copy prior owned wheels/locks to a new immutable-name directory first."""
    inputs = sorted(vendor.glob("*.whl"))
    for path in (vendor / "requirements.txt", *locks):
        if path.is_file() and path not in inputs:
            inputs.append(path)
    if not inputs:
        return None
    archive = root / "dist/preserved-wheelhouses" / (vendor.name + "-" + uuid.uuid4().hex)
    archive.mkdir(parents=True, exist_ok=False)
    for source in inputs:
        relative = source.relative_to(root)
        target = archive / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if hashlib.sha256(source.read_bytes()).digest() != hashlib.sha256(target.read_bytes()).digest():
            raise ValueError("wheelhouse_preservation_failed")
    return archive
