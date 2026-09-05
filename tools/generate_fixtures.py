"""Regenerate independent deterministic fixtures: uv run --with cbor2 --with cryptography tools/generate_fixtures.py"""
from pathlib import Path
import hashlib
import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
enc = lambda value: cbor2.dumps(value, canonical=True)
root = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
subject = Ed25519PrivateKey.from_private_bytes(bytes([2]) * 32)
public = lambda key: key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

def signed(claims, key, context):
    payload = enc(claims)
    protected = enc({1: -8})
    signature = key.sign(enc(["Signature1", protected, context, payload]))
    key.public_key().verify(signature, enc(["Signature1", protected, context, payload]))
    return enc([protected, {}, payload, signature])

cert = signed([1, bytes([3])*16, public(root), bytes([4])*16, public(subject), 100, 200,
               [["jobs", 3]], [1024, 8]], root, b"iroh-mq/certificate/v1")
message = signed([1, bytes([3])*16, public(subject), bytes([5])*16, "jobs", 1, 110, 150,
                  "opaque", 3, hashlib.sha256(b"abc").digest(), 1], subject, b"iroh-mq/message/v1")
hello = enc([1, cert, bytes([6])*16, 1024, 8, 300])
metadata = enc([1, bytes([7])*16, bytes([8])*16, message])
data = (len(metadata)+3).to_bytes(4,"big") + bytes([7,0,0,0]) + len(metadata).to_bytes(4,"big") + metadata + b"abc"
for name, value in {"certificate": cert, "message": message, "hello": hello, "data": data}.items():
    (OUT / f"{name}.hex").write_text(value.hex() + "\n")
print("Wrote four independently encoded and signed protocol fixtures.")
