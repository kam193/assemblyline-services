import ast
import base64
import binascii
import bz2
import codecs
import hashlib
import lzma
import re
import zlib

import cryptography
import cryptography.fernet
from ast_grep_py import SgRoot
from Crypto.Cipher import AES, PKCS1_OAEP, Blowfish, ChaCha20
from Crypto.PublicKey import RSA as RSA_Key
from Crypto.Util.Padding import unpad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class TransformationRejected(Exception):
    pass


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
    step = context.get("SLICE_STEP")
    return context[source][
        int(start) if start else None : int(end) if end else None : int(step) if step else None
    ]


def aes(config: dict, context: dict):
    source = config.get("source", "AES_SOURCE")
    mode_var = config.get("mode", "AES_MODE")
    mode_string = context.get(mode_var, "aes-256-gcm").upper()
    do_decode = config.get("decode", True)
    if "-" in mode_string:
        mode_string = mode_string.split("-")[-1]
    elif "_" in mode_string:
        mode_string = mode_string.split("_")[-1]

    if mode_string == "GCM":
        tag = context.get("AUTH_TAG", None)
        mode = modes.GCM(context.get("IV"), tag=tag)
    elif mode_string == "CBC":
        mode = modes.CBC(context.get("IV"))
    else:
        mode = modes.CTR(context.get("IV"))

    key = context.get("KEY")
    if not isinstance(key, bytes):
        key = bytes(key, "utf-8")
    cipher = Cipher(algorithms.AES(key), mode)
    decryptor = cipher.decryptor()
    source_data = context[source]
    if do_decode:
        return (decryptor.update(source_data) + decryptor.finalize()).decode("utf-8")
    return decryptor.update(source_data) + decryptor.finalize()


def encode(config: dict, context: dict):
    source = config.get("source", "DATA")
    encoding = config.get("encoding", "auto")
    if encoding in context:
        encoding = context[encoding]

    if encoding == "base64":
        data = base64.b64encode(context[source]).decode("utf-8")
    elif encoding == "hex":
        data = bytes.fromhex(context[source])
    elif encoding == "utf-8":
        if isinstance(context[source], str):
            data = bytes(context[source], "utf-8")
        else:
            data = context[source]
    elif encoding == "bytes-decode":
        data = bytes(context[source]).decode()
    elif encoding == "bytes":
        data = bytes(context[source])
    elif encoding == "unhexlify":
        data = binascii.unhexlify(context[source])
    elif encoding == "py-bytes":
        methods = [
            # lambda d: bytes.fromhex(d),
            lambda d: codecs.escape_decode(d)[0],
            # lambda d: bytes(d, "utf-8"),
        ]

        for method in methods:
            try:
                return method(context[source])
            except Exception:
                pass
        raise TransformationRejected("Cannot decode bytes")
    elif encoding == "auto":
        methods = [
            lambda d: bytes.fromhex(d),
            lambda d: codecs.escape_decode(d)[0],
            lambda d: bytes(d, "utf-8"),
        ]

        for method in methods:
            try:
                return method(context[source])
            except Exception:
                pass
        raise TransformationRejected("Cannot decode bytes")
    elif encoding == "zlib":
        data = zlib.decompress(context[source])
    elif encoding == "lzma":
        data = lzma.decompress(context[source])
    elif encoding == "bz2":
        data = bz2.decompress(context[source])
    elif encoding == "base64-bytes":
        data = base64.b64decode(context[source])
    else:
        data = codecs.decode(context[source], encoding)

    if "output" not in config:
        context[source] = data
    return data


def decode(config: dict, context: dict):
    source = config.get("source", "DATA")
    encoding = config.get("encoding", "unicode_escape")
    if encoding == encoding.upper():
        encoding = context.get(encoding, "utf-8")
    if any(c in encoding for c in "'\""):
        if encoding.startswith("b"):
            encoding = encoding[1:]
        encoding = encoding.replace("'", "").replace('"', "")

    return codecs.decode(context[source], encoding)


def fernet(config: dict, context: dict):
    source = config.get("source", "FERNET_SOURCE")
    cipher = cryptography.fernet.Fernet(context.get("FERNET_KEY"))
    return cipher.decrypt(context[source]).decode("utf-8")


def encode_list(config: dict, context: dict):
    encoding = config.get("encoding", "int")
    separators = config.get("separators", ",")
    source = config.get("source", "DATA")

    data = []
    for item in context[source]:
        if item in separators:
            continue
        if encoding == "int":
            data.append(int(item))
        elif encoding == "str":
            data.append(str(item))
        elif encoding == "base64":
            data.append(base64.b64encode(bytes(item, "utf-8")).decode("utf-8"))
        elif encoding == "hex":
            data.append(bytes.fromhex(item))
        elif encoding == "utf-8":
            data.append(bytes(item, "utf-8"))

    return data


def reverse(config: dict, context: dict):
    source = config.get("source", "DATA")
    return context[source][::-1]


def quote(config: dict, context: dict):
    source = config.get("source", "DATA")
    # style = config.get("style", "double")
    return repr(context[source])


def output(config: dict, context: dict):
    source = config.get("source", "DATA")
    return context[source]


def concat(config: dict, context: dict):
    sources = config.get("sources", ["DATA"])
    separator = config.get("separator", ".")
    return separator.join(context[source] for source in sources)


def str_concat(config: dict, context: dict):
    left_op = config.get("left_op", "LEFT_OP")
    right_op = config.get("right_op", "RIGHT_OP")

    left = context[left_op]
    right = context[right_op]

    if type(left) is type(right):
        return left + right

    # for now, assume one is bytes and the other is str
    if isinstance(left, str):
        # check if it's just a string representation of a bytestring
        try:
            tmp = ast.literal_eval(left)
        except Exception:
            tmp = None
        if isinstance(tmp, bytes):
            left = tmp
        else:
            left = left.encode()
    if isinstance(right, str):
        # check if it's just a string representation of a bytestring
        try:
            tmp = ast.literal_eval(right)
        except Exception:
            tmp = None
        if isinstance(tmp, bytes):
            right = tmp
        else:
            right = right.encode()
    return left + right


MATH_ALLOWED = "0123456789/+-*^(). ><=_~ \tnot"
MATH_GUARD = re.compile(r"[\s/+\-*^](?!(not\s)|[0-9/+\-*^(). ><=~ \t])\S")
MATH_BOOL_EXPR = re.compile(r"^\s*(not\s{1,}|)(True|False)\s*$")


def math_eval(config: dict, context: dict):
    source = config.get("source", "MATH_SOURCE")
    if source not in context:
        return None
    data = context[source]
    if MATH_BOOL_EXPR.match(data):
        return bool(eval(data, {}, {}))
    if not isinstance(data, str) or any(c not in MATH_ALLOWED for c in data):
        raise TransformationRejected("Not allowed chars found")
    if MATH_GUARD.search(data):
        raise TransformationRejected("Not allowed expression found")
    try:
        return eval(data, {}, {})
    except Exception as exc:
        raise TransformationRejected(f"Math eval failed: {exc}")


def collect_var(config: dict, context: dict):
    source_var = config.get("source", "VAR")
    source_value = config.get("value", "VALUE")
    parse = config.get("parse", "no")
    val = context[source_value]

    name = context[source_var]
    if parse == "python":
        obj = ast.parse(name).body[0].value
        if hasattr(obj, "id"):
            name = obj.id
        else:
            return {}
        val = ast.literal_eval(val)

    return {name: val}


def py_ast_concat(config: dict, context: dict):
    """Parse AST and concat nodes using static values or variables from context["vars"]"""

    source = config.get("source", "ARGS")
    tree = ast.parse(context[source])
    result = []
    stack = []
    stack.append(tree)

    while stack:
        node = stack.pop(0)
        if isinstance(node, ast.Constant):
            result.append(node.s)
        elif isinstance(node, ast.Name):
            if "vars" not in context:
                raise TransformationRejected("Context['vars'] not found")
            value = context["vars"].get(node.id, "<MISSED>")
            if value == "<MISSED>":
                raise TransformationRejected(f"Variable {node.id} not found in context['vars']")
            result.append(context["vars"][node.id])
        elif isinstance(node, ast.BinOp):
            stack.insert(0, node.right)
            stack.insert(0, node.left)
        else:
            for child in ast.iter_child_nodes(node):
                stack.insert(0, child)

    if len(result) == 0:
        return ""
    elif isinstance(result[0], str):
        return "".join(result)
    else:
        return b"".join(result)


def replace_in_match(config: dict, context: dict):
    source = config.get("source", "INPUT")
    replace = config.get("match", "DATA")
    return context["match"].replace(context[source], context[replace])


def replace_in_ctx(config: dict, context: dict):
    to_replace = config.get("to_replace", "TO_REPLACE")
    source = config.get("source", "INPUT")
    replace = config.get("match", "DATA")
    return context[to_replace].replace(context[source], context[replace])


def substitute_var(config: dict, context: dict):
    source = config.get("source", "INPUT")
    pattern = config.get("pattern", "PATTERN")
    language = config.get("language", "python")
    replacement = config.get("replacement", "REPLACEMENT")
    ignore_missed = config.get("ignore_missed", False)

    if not replacement.startswith("$"):
        replacement = context[replacement]

    try:
        pattern_val = context[pattern]
    except KeyError:
        if ignore_missed:
            return context[source]
        raise

    sg = SgRoot(context[source], language)
    root = sg.root()
    ret = root.commit_edits(
        [m.replace(replacement) for m in root.find_all(pattern=pattern_val, kind="identifier")]
    )
    return ret


def produce(config: dict, context: dict):
    # source = config.get("source", "INPUT")
    template = config.get("template", "TEMPLATE")
    return template.format(**context)


def literal_eval(config: dict, context: dict):
    source = config.get("source", "DATA")
    return ast.literal_eval(context[source])


def dequote(config: dict, context: dict):
    source = config.get("source", "DATA")
    should_decode = config.get("decode", True)
    result = ast.literal_eval(context[source])
    if isinstance(result, bytes) and should_decode:
        return result.decode("utf-8")
    return result


ascii_varname = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*$")


def rename(config: dict, context: dict):
    prefix = config.get("prefix", "renabmed_during_deobfuscation")
    source = config.get("source", "VAR")
    source_value = context[source]
    if "rename_cache" not in context["cache"]:
        context["cache"]["rename_cache"] = {}
    if source_value in context["cache"]["rename_cache"]:
        var_config = context["cache"]["rename_cache"][source_value]
    else:
        new_name = f"{prefix}_{len(context['cache']['rename_cache'])}"
        try:
            parsed_name = ast.parse(source_value).body[0].value.id
            # catches cases when name is changed by normalization
            if ascii_varname.match(parsed_name):
                new_name = parsed_name
            var_config = (new_name, True)
        except Exception as exc:
            print(exc)
            var_config = (new_name, False)
        context["cache"]["rename_cache"][source_value] = var_config
    return new_name


def noop_ifs(config: dict, context: dict):
    if_result = config.get("if_result", "IF_RESULT")
    elif_result = config.get("elif_result", "ELIF_RESULT")

    if context[if_result]:
        code = config.get("if_code", "IF_CODE")
        return context[code]
    elif context.get(elif_result, False):
        code = config.get("elif_code", "ELIF_CODE")
        return context[code]
    else:
        code = config.get("else_code", "ELSE_CODE")
        return context.get(code, "pass")


def join_chr_xor(config: dict, context: dict) -> str:
    data_list = config.get("source", "DATA")
    xor_num = config.get("xor", "XOR_NUM")

    if xor_num is not None:
        xor_value = context[xor_num]
        if not isinstance(xor_value, int):
            xor_value = int(xor_value)

        return "".join(chr(i ^ xor_value) for i in context[data_list])
    return "".join(chr(i) for i in context[data_list])


def chr_(config: dict, context: dict) -> str:
    field = config.get("source", "DATA")
    data = context[field]
    if not isinstance(data, int):
        data = int(data)
    return chr(data)


def rsa(config: dict, context: dict) -> bytes:
    data = config.get("source", "DATA")
    key = config.get("key", "KEY")
    block_size = config.get("block_size", "BLOCK_SIZE")
    mode = config.get("mode", "PKCS1_OAEP")

    if mode != "PKCS1_OAEP":
        raise TransformationRejected("Unsupported RSA mode")

    rsa_cipher = PKCS1_OAEP.new(RSA_Key.import_key(context[key]))
    decrypted_data = bytearray()
    block_size = int(context[block_size])
    data = context[data]
    for block_start in range(0, len(data), block_size):
        block = data[block_start : block_start + block_size]
        decrypted_data.extend(rsa_cipher.decrypt(block))
    return bytes(decrypted_data)


def chacha20(config: dict, context: dict) -> bytes:
    data = config.get("source", "DATA")
    key = config.get("key", "KEY")
    nonce = config.get("nonce", "NONCE")

    cipher = ChaCha20.new(key=context[key], nonce=context[nonce])
    return cipher.decrypt(context[data])


def blowfish(config: dict, context: dict) -> bytes:
    data = config.get("source", "DATA")
    key = config.get("key", "KEY")
    iv = config.get("nonce", "IV")
    mode = config.get("mode", "MODE_CBC")

    if mode != "MODE_CBC":
        raise TransformationRejected("Unsupported Blowfish mode")

    cipher = Blowfish.new(key=context[key], mode=Blowfish.MODE_CBC, iv=context[iv])
    return cipher.decrypt(context[data])


def unpad_function(config: dict, context: dict) -> bytes:
    data = config.get("source", "DATA")
    block = config.get("block", "BLOCK_SIZE")

    block_size = None
    if context[block] == "Blowfish.block_size":
        block_size = Blowfish.block_size
    elif context[block] == "AES.block_size":
        block_size = AES.block_size
    else:
        raise TransformationRejected("Unsupported block size")

    return unpad(context[data], block_size)
