"""Shared AL test helpers for the ClamAV service."""

import hashlib
import os
import shutil
import tempfile

from assemblyline.common import forge
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task

SERVICE_NAME = "ClamAV-Service"
_FILEINFO_KEYS = ("magic", "md5", "mime", "sha1", "sha256", "size", "type", "uri_info")
_identify = None


def identify():
    global _identify
    if _identify is None:
        _identify = forge.get_identify(use_cache=False)
    return _identify


def stage_file(path: str) -> str:
    sha256 = hashlib.sha256(open(path, "rb").read()).hexdigest()
    target = os.path.join(tempfile.gettempdir(), sha256)
    if not os.path.exists(target):
        shutil.copyfile(path, target)
    return sha256


def build_request(path, *, config=None, params=None, filename=None):
    stage_file(path)
    fileinfo = {
        k: v
        for k, v in identify()
        .fileinfo(path, skip_fuzzy_hashes=True, calculate_entropy=False)
        .items()
        if k in _FILEINFO_KEYS
    }
    service_config = {p.name: p.default for p in helper.get_service_attributes().submission_params}
    service_config.update(params or {})
    task = ServiceTask(
        {
            "sid": 1,
            "metadata": {},
            "deep_scan": False,
            "depth": 0,
            "service_name": SERVICE_NAME,
            "service_config": service_config,
            "fileinfo": fileinfo,
            "filename": filename or os.path.basename(path),
            "min_classification": "TLP:C",
            "max_files": 501,
            "ttl": 3600,
            "temporary_submission_data": [],
            "tags": [],
        }
    )
    return ServiceRequest(Task(task))


def eicar_bytes() -> bytes:
    parts = (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}",
        "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    return "".join(parts).encode()


def write_hdb_signature(
    directory: str, content: bytes, name: str, filename: str = "custom.hdb"
) -> None:
    """Write a minimal ClamAV hash-based signature (.hdb) matching `content` exactly,
    so a daemon loading only this file can detect it without any real virus database."""
    digest = hashlib.md5(content).hexdigest()
    with open(os.path.join(directory, filename), "w") as f:
        f.write(f"{digest}:{len(content)}:{name}\n")
