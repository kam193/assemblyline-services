import os
import time
import warnings

import pytest
import yaml
from service.controller import (
    ASTGrepDeobfuscationController,
    ASTGrepLSPController,
    ASTGrepScanController,
)

RULES_DIR = "./rules/"


@pytest.fixture(scope="module")
def deobfuscator():
    return ASTGrepDeobfuscationController(rules_dirs=[RULES_DIR], min_length_for_confirmed=5)


@pytest.fixture(scope="module")
def lsp_controller():
    lsp = ASTGrepLSPController(rules_dir=[RULES_DIR])

    wait_start = time.monotonic()
    while not lsp.ready and time.monotonic() - wait_start < 10:
        time.sleep(1)
    if not lsp.ready:
        raise RuntimeError("LSP did not start")
    try:
        yield lsp
    finally:
        lsp.stop()


@pytest.fixture(scope="module")
def scan_controller():
    scan = ASTGrepScanController(rules_dir=[RULES_DIR])
    return scan


def detect_sample(
    controller, example, deobfuscator, expected=True, metadata_field="extended-obfuscation"
):
    language = f"code/{example.split('/')[-2]}"
    results = list(controller.process_file(f"{example}.in", language, retry=False))

    detection_result = False
    for result in results:
        rule_id = result.get("ruleId", result.get("check_id"))
        metadata = deobfuscator._metadata.get(rule_id, {})
        if metadata.get(metadata_field, False):
            detection_result = True
            break

    if not detection_result:
        rule_id = "/"

    assert detection_result == expected, (
        f"Sample was {'not' if expected else ''} detected as {metadata_field} by {rule_id}"
    )


def rstrip_lines(data: str | list[str]) -> str:
    if not isinstance(data, list):
        data = data.splitlines()
    return "\n".join(s.rstrip() for s in data)


@pytest.fixture
def deobfuscate_example(deobfuscator):
    def _check_example(
        path: str,
        language: str | None = None,
        warning_time: int = 5,
        check_confirmed: bool = False,
        check_output: bool = True,
        confirmed_obfuscation: bool = True,
    ):
        if not language:
            lang_name = os.path.relpath(path, "./tests").split("/")[1]
            language = f"code/{lang_name}"
        results = list(deobfuscator.deobfuscate_file(f"{path}.in", language))
        if check_output:
            assert rstrip_lines(results[-1][0].strip()) == rstrip_lines(
                open(f"{path}.out", "r").read().strip()
            )
        if deobfuscator.work_time > warning_time:
            warnings.warn(f"Deobfuscation took {deobfuscator.work_time:.3f} seconds")
        assert deobfuscator.work_time < deobfuscator.deobfuscation_timeout, (
            "Deobfuscation took too long"
        )
        if check_confirmed:
            confirmed = True if deobfuscator.get_score() >= 100 else False
            assert confirmed == confirmed_obfuscation, (
                f"Deobfuscation was {'not' if confirmed_obfuscation else ''}"
                f" confirmed by {'/'.join(f'{r}[{s}]' for r, s in deobfuscator._get_scoring_details().items())}"
            )
        return results

    return _check_example


def _list_examples(group: str):
    examples = []
    for root, _, files in os.walk(f"./tests/{group}_examples/"):
        for file in files:
            if file.endswith(".in"):
                examples.append(os.path.join(root, file[:-3]))
    return examples


@pytest.mark.parametrize(
    "example",
    _list_examples("autofixes"),
)
def test_autofixes_cases(deobfuscate_example, example):
    deobfuscate_example(example)


@pytest.mark.parametrize(
    "example",
    _list_examples("simple"),
)
def test_simple_cases(deobfuscate_example, example):
    """Test for every rule"""
    deobfuscate_example(example)


def test_all_extended_rules_have_simple_tests():
    # read all rules and collect IDs
    rules = []
    for root, _, files in os.walk(f"{RULES_DIR}/extended/"):
        for file in files:
            if file.endswith(".yml") or file.endswith(".yaml"):
                with open(os.path.join(root, file), "r") as f:
                    reader = yaml.safe_load_all(f)
                    for doc in reader:
                        if not doc:
                            continue
                        rules.append(doc["id"])

    assert sorted(rules) == sorted(set(rules)), "Duplicated rule ID"

    examples = [os.path.basename(e) for e in _list_examples("simple")]

    assert sorted(examples) == sorted(rules), "Rules does not match basic test examples"


@pytest.mark.slow
@pytest.mark.skipif(
    not os.path.exists("./tests/dangerous_examples"), reason="Samples are not accessible"
)
@pytest.mark.parametrize(
    "example",
    _list_examples("dangerous"),
)
def test_real_samples(deobfuscate_example, example):
    """Tests on real samples"""
    check_confirmed = "NOCONFIRMATION" not in example
    max_retries = 3 if "UNSTABLE" in example else 1
    current_try = 0
    while current_try < max_retries:
        try:
            deobfuscate_example(example, check_confirmed=check_confirmed)
            break
        except AssertionError:
            current_try += 1
            if current_try >= max_retries:
                raise


@pytest.mark.skipif(
    not os.path.exists("./tests/dangerous_examples"), reason="Samples are not accessible"
)
@pytest.mark.parametrize(
    "example",
    _list_examples("dangerous"),
)
def test_lsp_detects_real_samples(lsp_controller, example, deobfuscator):
    """Tests on real samples"""
    detect_sample(lsp_controller, example, deobfuscator)


@pytest.mark.parametrize(
    "example",
    _list_examples("other"),
)
def test_other_cases(deobfuscate_example, example):
    """Test for every rule"""
    deobfuscate_example(example)


@pytest.mark.parametrize(
    "example",
    _list_examples("detection"),
)
def test_lsp_detects_prepared_samples(lsp_controller, example, deobfuscator):
    """Tests on prepared samples"""
    detect_sample(lsp_controller, example, deobfuscator)


@pytest.mark.parametrize(
    "example",
    _list_examples("detection"),
)
def test_scan_detects_prepared_samples(scan_controller, example, deobfuscator):
    """Tests on prepared samples"""
    detect_sample(scan_controller, example, deobfuscator)


@pytest.mark.parametrize(
    "example",
    _list_examples("negative"),
)
def test_negative_cases(scan_controller, example, deobfuscator):
    """Those samples should not be detected as confirmed obfuscation"""
    detect_sample(
        scan_controller,
        example,
        deobfuscator,
        expected=False,
        metadata_field="confirmed-obfuscation",
    )


@pytest.mark.skipif(
    not os.path.exists("./tests/real_negative_examples"), reason="Samples are not accessible"
)
@pytest.mark.parametrize(
    "example",
    _list_examples("real_negative"),
)
def test_negative_real_cases(deobfuscate_example, example):
    """Those samples should not be detected as confirmed obfuscation after deobfuscation"""
    deobfuscate_example(
        example, check_output=False, confirmed_obfuscation=False, check_confirmed=True
    )
