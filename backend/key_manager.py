import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_kek_hex = os.environ.get('KRYPT_VAULT_KEK')

if not _kek_hex:
    raise Exception("❌ KRYPT_VAULT_KEK not set in environment")

MASTER_KEK = bytes.fromhex(_kek_hex)


def generate_dek():
    return os.urandom(32)


def encrypt_dek_with_kek(dek):
    nonce = os.urandom(12)
    ct = AESGCM(MASTER_KEK).encrypt(nonce, dek, None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_dek_with_kek(enc_b64):
    raw = base64.b64decode(enc_b64)
    return AESGCM(MASTER_KEK).decrypt(raw[:12], raw[12:], None)

