import pytest
from service.controller import ASTGrepDeobfuscationController


@pytest.fixture
def deobfuscator():
    return ASTGrepDeobfuscationController(rules_dirs=["./rules/"])


@pytest.fixture
def deobfuscate_example(deobfuscator):
    def _check_example(example, language="code/python"):
        results = list(deobfuscator.deobfuscate_file(f"./tests/examples/{example}.in", language))
        assert results[-1][0] == open(f"./tests/examples/{example}.out", "r").read()
        return results

    return _check_example


@pytest.mark.parametrize("example", ["simple_fernet", "simple_cc"])
def test_simple_cases(deobfuscate_example, example):
    deobfuscate_example(example)
