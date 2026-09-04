"""Versioned envelope encryption for stored secrets.

Every secret is sealed with a fresh random data-encryption key (DEK); the DEK is
then wrapped with a key-encryption key (KEK) supplied by the deployment. The
sealed value is a compact JSON envelope that records which KEK wrapped it, so
KEKs can be rotated without a flag day: add the new key as primary, re-seal on
write, and drop the old key once nothing references it.

KEK source (in priority order):
  1. ARTEMIS_ENCRYPTION_KEYS = "id:base64key,id2:base64key2" (first entry is
     primary; the rest are decrypt-only, for rotation).
  2. ARTEMIS_ENCRYPTION_KEY  = "base64key"  (id defaults to "default").
  3. ARTEMIS_ENCRYPTION_KEY_FILE = path to a file containing a base64 key.

A key is 32 raw bytes, base64 or hex encoded. With no KEK configured the module
is "unconfigured": sealing raises, and the app factory refuses to serve
production unless ARTEMIS_ALLOW_INSECURE=1 is explicitly set.
"""

import base64
import binascii
import json
import os
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_VERSION = 1
_ENVELOPE_PREFIX = "enc:v1:"

_lock = threading.Lock()
_keyring = None  # dict: kek_id -> 32 raw bytes
_primary_id = None


class CryptoError(RuntimeError):
    pass


class CryptoNotConfigured(CryptoError):
    pass


def _decode_key(material):
    material = material.strip()
    for decoder in (base64.b64decode, bytes.fromhex):
        try:
            raw = decoder(material)
        except (binascii.Error, ValueError):
            continue
        if len(raw) == 32:
            return raw
    raise CryptoError("encryption key must decode to 32 bytes (base64 or hex)")


def _load_keyring():
    keys = {}
    primary = None

    spec = os.environ.get("ARTEMIS_ENCRYPTION_KEYS", "").strip()
    if spec:
        for entry in spec.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if ":" not in entry:
                raise CryptoError("ARTEMIS_ENCRYPTION_KEYS entries must be 'id:key'")
            kek_id, material = entry.split(":", 1)
            keys[kek_id.strip()] = _decode_key(material)
            if primary is None:
                primary = kek_id.strip()

    single = os.environ.get("ARTEMIS_ENCRYPTION_KEY", "").strip()
    if not single:
        key_file = os.environ.get("ARTEMIS_ENCRYPTION_KEY_FILE", "").strip()
        if key_file and os.path.exists(key_file):
            with open(key_file) as handle:
                single = handle.read().strip()
    if single:
        keys.setdefault("default", _decode_key(single))
        if primary is None:
            primary = "default"

    return keys, primary


def _keyring_state():
    global _keyring, _primary_id
    if _keyring is None:
        with _lock:
            if _keyring is None:
                _keyring, _primary_id = _load_keyring()
    return _keyring, _primary_id


def reset_cache():
    """Forget the cached keyring (tests mutate the environment)."""
    global _keyring, _primary_id
    with _lock:
        _keyring = None
        _primary_id = None


def is_configured():
    keyring, primary = _keyring_state()
    return bool(keyring and primary)


def active_key_id():
    _, primary = _keyring_state()
    return primary


def seal(plaintext):
    """Return an ``enc:v1:<b64 json>`` envelope for a str/bytes secret."""
    if plaintext is None:
        return None
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    keyring, primary = _keyring_state()
    if not primary:
        raise CryptoNotConfigured(
            "no encryption key configured; set ARTEMIS_ENCRYPTION_KEY"
        )
    kek = keyring[primary]

    dek = AESGCM.generate_key(bit_length=256)
    dek_nonce = os.urandom(12)
    nonce = os.urandom(12)
    wrapped = AESGCM(kek).encrypt(dek_nonce, dek, primary.encode("utf-8"))
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, None)

    envelope = {
        "v": ENVELOPE_VERSION,
        "k": primary,
        "dn": base64.b64encode(dek_nonce).decode("ascii"),
        "wd": base64.b64encode(wrapped).decode("ascii"),
        "n": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
    }
    return _ENVELOPE_PREFIX + base64.b64encode(
        json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def is_sealed(value):
    return isinstance(value, str) and value.startswith(_ENVELOPE_PREFIX)


def open_envelope(value):
    """Return the plaintext ``str`` for a sealed envelope."""
    if value is None:
        return None
    if not is_sealed(value):
        raise CryptoError("value is not a sealed envelope")

    keyring, _ = _keyring_state()
    try:
        envelope = json.loads(base64.b64decode(value[len(_ENVELOPE_PREFIX):]))
    except (binascii.Error, ValueError) as exc:
        raise CryptoError("corrupt secret envelope") from exc

    kek_id = envelope.get("k")
    kek = keyring.get(kek_id)
    if kek is None:
        raise CryptoError(f"no key '{kek_id}' available to decrypt this secret")

    try:
        dek = AESGCM(kek).decrypt(
            base64.b64decode(envelope["dn"]),
            base64.b64decode(envelope["wd"]),
            (kek_id or "").encode("utf-8"),
        )
        plaintext = AESGCM(dek).decrypt(
            base64.b64decode(envelope["n"]),
            base64.b64decode(envelope["ct"]),
            None,
        )
    except (InvalidTag, KeyError, binascii.Error, ValueError) as exc:
        raise CryptoError("secret could not be decrypted (wrong key or tampered)") from exc

    return plaintext.decode("utf-8")


def needs_reseal(value):
    """True when a sealed value is not wrapped by the current primary key."""
    if not is_sealed(value):
        return True
    try:
        envelope = json.loads(base64.b64decode(value[len(_ENVELOPE_PREFIX):]))
    except (binascii.Error, ValueError):
        return True
    return envelope.get("k") != active_key_id()


def generate_key():
    """A fresh base64 KEK, for `docs`/setup output."""
    return base64.b64encode(os.urandom(32)).decode("ascii")
