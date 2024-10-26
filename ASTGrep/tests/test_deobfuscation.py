import os
import warnings

import pytest
import yaml
from service.controller import ASTGrepDeobfuscationController, ASTGrepLSPController

RULES_DIR = "./rules/"


@pytest.fixture(scope="module")
def deobfuscator():
    return ASTGrepDeobfuscationController(rules_dirs=[RULES_DIR], min_length_for_confirmed=5)


@pytest.fixture(scope="module")
def lsp_controller():
    lsp = ASTGrepLSPController(rules_dir=[RULES_DIR])
    try:
        yield lsp
    finally:
        lsp.stop()


@pytest.fixture
def deobfuscate_example(deobfuscator):
    def _check_example(
        path: str, language: str | None = None, warning_time: int = 5, check_confirmed: bool = False
    ):
        if not language:
            lang_name = os.path.relpath(path, "./tests").split("/")[1]
            language = f"code/{lang_name}"
        results = list(deobfuscator.deobfuscate_file(f"{path}.in", language))
        assert results[-1][0].strip() == open(f"{path}.out", "r").read().strip()
        if deobfuscator.work_time > warning_time:
            warnings.warn(f"Deobfuscation took {deobfuscator.work_time:.3f} seconds")
        assert (
            deobfuscator.work_time < deobfuscator.deobfuscation_timeout
        ), "Deobfuscation took too long"
        if check_confirmed:
            assert deobfuscator.confirmed_obfuscation is True, "Deobfuscation was not confirmed"
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
    deobfuscate_example(example, check_confirmed=check_confirmed)


@pytest.mark.skipif(
    not os.path.exists("./tests/dangerous_examples"), reason="Samples are not accessible"
)
@pytest.mark.parametrize(
    "example",
    _list_examples("dangerous"),
)
def test_lsp_detects_real_samples(lsp_controller, example, deobfuscator):
    """Tests on real samples"""
    language = f"code/{example.split('/')[-2]}"
    results = list(lsp_controller.process_file(f"{example}.in", language, retry=False))

    extended_obfuscation = False
    for result in results:
        metadata = deobfuscator._metadata.get(result["check_id"], {})
        if metadata.get("extended-obfuscation", False):
            extended_obfuscation = True
            break
    assert extended_obfuscation is True, "Sample was not detected as potentially obfuscated"


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
    language = f"code/{example.split('/')[-2]}"
    results = list(lsp_controller.process_file(f"{example}.in", language, retry=False))

    extended_obfuscation = False
    for result in results:
        metadata = deobfuscator._metadata.get(result["check_id"], {})
        if metadata.get("extended-obfuscation", False):
            extended_obfuscation = True
            break
    assert extended_obfuscation is True, "Sample was not detected as potentially obfuscated"
