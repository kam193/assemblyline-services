"""Shared AL test helpers. See .claude/skills/al-service-testing."""

import hashlib
import os
import pathlib
import shutil
import tempfile

import cart
from assemblyline.common import forge
from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_service_utilities.testing.helper import TestHelper
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task

SERVICE_NAME = "template-service"
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


def build_request(path, *, config=None, params=None, temp_data=None, filename=None, tags=None):
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
            "temporary_submission_data": [
                {"name": k, "value": v} for k, v in (temp_data or {}).items()
            ],
            "tags": [
                {"type": tag_type, "value": value, "short_type": tag_type.rsplit(".", 1)[-1]}
                for tag_type, values in (tags or {}).items()
                for value in values
            ],
        }
    )
    return ServiceRequest(Task(task))


def _stage_samples(source):
    """tests/samples may hold ready <sha256>.cart files and/or plain files, which get carted."""
    target = pathlib.Path(tempfile.mkdtemp(prefix="samples_"))
    if not source.is_dir():
        return target
    for path in source.iterdir():
        if path.suffix == ".cart":
            shutil.copyfile(path, target / path.name)
        elif path.is_file():
            sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
            with open(path, "rb") as plain, open(target / f"{sha256}.cart", "wb") as carted:
                cart.pack_stream(plain, carted)
    return target


def build_test_helper(service_path="service.al_run.AssemblylineService"):
    root = pathlib.Path(__file__).resolve().parent.parent
    test_helper = TestHelper(
        load_module_by_path(service_path, str(root)),
        str(root / "tests" / "results"),
        str(_stage_samples(root / "tests" / "samples")),
    )
    # TestHelper re.match()es the manifest filetype, which is invalid regex for "*"
    for heuristic in test_helper.heuristics.values():
        if heuristic.filetype == "*":
            heuristic.filetype = ".*"
    return test_helper
