import base64
import hashlib

import cryptography
import cryptography.fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def scrypt(config: dict, context: dict):
    return hashlib.scrypt(
        bytes(context.get("MASTER_KEY"), "utf-8"),
        salt=context.get("SALT"),
        n=int(context.get("OPT_N")),
        r=int(context.get("OPT_R")),
        p=int(context.get("OPT_P")),
        dklen=int(context.get("KEY_LENGTH")),
    )


def slice(config: dict, context: dict):
    source = config.get("source", "SLICE_SOURCE")
    start = context.get("SLICE_START", 0)
    end = context.get("SLICE_END")
    return context[source][int(start) if start else None : int(end) if end else None]


def aes(config: dict, context: dict):
    source = config.get("source", "AES_SOURCE")
    mode_string = context.get("AES_MODE", "aes-256-gcm").upper()
    if "-" in mode_string:
        mode_string = mode_string.split("-")[-1]
    if mode_string == "GCM":
        tag = context.get("AUTH_TAG", None)
        mode = modes.GCM(context.get("IV"), tag=tag)
    else:
        mode = modes.CTR(context.get("IV"))

    key = context.get("KEY")
    if not isinstance(key, bytes):
        key = bytes(key, "utf-8")
    cipher = Cipher(algorithms.AES(key), mode)
    decryptor = cipher.decryptor()
    source_data = context[source]
    return (decryptor.update(source_data) + decryptor.finalize()).decode("utf-8")


def encode(config: dict, context: dict):
    source = config.get("source", "ENCODE_SOURCE")
    encoding = config.get("encoding", "utf-8")
    if encoding in context:
        encoding = context[encoding]

    if encoding == "base64":
        data = base64.b64encode(context[source]).decode("utf-8")
    elif encoding == "hex":
        data = bytes.fromhex(context[source])
    elif encoding == "utf-8":
        data = bytes(context[source], "utf-8")

    if "output" not in config:
        context[source] = data


def fernet(config: dict, context: dict):
    source = config.get("source", "FERNET_SOURCE")
    cipher = cryptography.fernet.Fernet(context.get("FERNET_KEY"))
    return cipher.decrypt(context[source]).decode("utf-8")
