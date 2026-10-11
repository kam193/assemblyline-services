import hashlib
import os
import pathlib
import shutil
import tempfile
from types import SimpleNamespace

import cart
import yaml
from assemblyline.common import forge
from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_service_utilities.testing.helper import TestHelper
from assemblyline_v4_service.common import helper
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task
from service import al_run
from service.al_run import AssemblylineService

RULES = pathlib.Path(__file__).parent / "rules"
WORKSPACE = os.path.join(tempfile.gettempdir(), "semgrep_test_workspace")
SERVICE_NAME = "Semgrep"
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


def matches(request):
    """Rule section title -> titles of its match subsections, for the first result section."""
    return {
        section.title_text: [match.title_text for match in section.subsections]
        for section in request.result.sections[0].subsections
    }


def _without_volatile_fields(controller):
    process_file = controller.process_file

    def wrapper(*args, **kwargs):
        yield from process_file(*args, **kwargs)
        if isinstance(controller.last_results, dict):
            controller.last_results.pop("time", None)
            controller.last_results.pop("version", None)

    return wrapper


def _read_rules(path):
    with open(path) as f:
        return [yaml.safe_load(chunk) for chunk in f.read().split("#SIGNATURE-DELIMITER#")]


class RulesInjectedService(AssemblylineService):
    """Service with rules from tests/rules/, standing in for the updater and its signature API."""

    def __init__(self, config=None):
        al_run.RULES_DIR = tempfile.mkdtemp(prefix="semgrep_rules_")
        super().__init__(config)
        os.makedirs(WORKSPACE, exist_ok=True)
        for controller in (self._semgrep, self._fallback_semgrep):
            if controller:
                controller.workspace = SimpleNamespace(name=WORKSPACE)
                controller.process_file = _without_volatile_fields(controller)

    def start(self):
        super().start()
        self.rules_list = sorted(str(path) for path in RULES.iterdir())
        self.signatures_meta = {
            rule["id"]: {"classification": self.classification.UNRESTRICTED, "status": "DEPLOYED"}
            for path in self.rules_list
            for rule in _read_rules(path)
        }
        self._load_rules()

    def _cleanup(self):
        super()._cleanup()
        self.stop()
        shutil.rmtree(al_run.RULES_DIR, ignore_errors=True)
        shutil.rmtree(WORKSPACE, ignore_errors=True)


def _cart_samples(source):
    target = pathlib.Path(tempfile.mkdtemp(prefix="semgrep_samples_"))
    for path in source.glob("*.data"):
        sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        with open(path, "rb") as plain, open(target / f"{sha256}.cart", "wb") as carted:
            cart.pack_stream(plain, carted)
    return target


def build_test_helper():
    root = pathlib.Path(__file__).resolve().parent.parent
    helper_ = TestHelper(
        load_module_by_path("tests.al.RulesInjectedService", str(root)),
        str(root / "tests" / "results"),
        str(_cart_samples(root / "tests" / "data")),
    )
    for heuristic in helper_.heuristics.values():
        if heuristic.filetype == "*":
            heuristic.filetype = ".*"
    return helper_
