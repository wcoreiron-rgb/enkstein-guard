"""Operator-controlled Ed25519 artifact signatures with an external trust anchor.

The public key must be distributed independently. A signature is not a security
certification, and generating a key does not establish third-party trust.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from .vault import _check_private


def create_signing_key(path):
    path=Path(path)
    _check_private(path.parent,directory=True)
    key=Ed25519PrivateKey.generate()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"wb") as stream:
        stream.write(key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption()))
        stream.flush()
        os.fsync(stream.fileno())
    return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)


def _digest(path):
    digest=hashlib.sha256()
    size=0
    with Path(path).open("rb") as stream:
        while chunk:=stream.read(1024*1024):
            size+=len(chunk)
            digest.update(chunk)
    return size,digest.hexdigest()


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()


def sign_artifacts(key_path,artifacts):
    key_path=Path(key_path)
    _check_private(key_path.parent,directory=True)
    _check_private(key_path)
    key=Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    records=[]
    names=set()
    for artifact in artifacts:
        path=Path(artifact)
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*",path.name) or path.name in names:
            raise ValueError("invalid_or_duplicate_artifact_name")
        names.add(path.name)
        size,digest=_digest(path)
        records.append({"name":path.name,"bytes":size,"sha256":digest})
    if not records:
        raise ValueError("empty_release")
    payload={"schema_version":1,"artifacts":sorted(records,key=lambda r:r["name"])}
    return {"payload":payload,"signature":base64.b64encode(key.sign(_canonical(payload))).decode()}


def verify_artifacts(envelope,public_key,directory):
    if type(envelope) is not dict or set(envelope)!={"payload","signature"}:
        raise ValueError("invalid_release")
    key=Ed25519PublicKey.from_public_bytes(public_key)
    key.verify(base64.b64decode(envelope["signature"],validate=True),_canonical(envelope["payload"]))
    payload=envelope["payload"]
    if set(payload)!={"schema_version","artifacts"} or payload["schema_version"]!=1 or not payload["artifacts"]:
        raise ValueError("invalid_release")
    names=set()
    for record in payload["artifacts"]:
        name=record["name"]
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*",name) or name in names:
            raise ValueError("invalid_artifact_name")
        names.add(name)
        size,digest=_digest(Path(directory)/name)
        if size!=record["bytes"] or digest!=record["sha256"]:
            raise ValueError("artifact_verification_failed")
    return True
