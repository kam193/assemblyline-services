import pytest
from service.controller import ASTGrepDeobfuscationController


@pytest.fixture
def deobfuscator():
    return ASTGrepDeobfuscationController(rules_dirs=["./rules/"])


@pytest.fixture
def deobfuscate_example(deobfuscator):
    def _check_example(name: str, group: str, language: str = "code/python"):
        results = list(deobfuscator.deobfuscate_file(f"./tests/examples/{group}/{name}.in", language))
        assert results[-1][0] == open(f"./tests/examples/{group}/{name}.out", "r").read()
        return results

    return _check_example


# TODO: Simple cases should reflect every rule
# TODO: Structure of samples to reflect the structure of the rules

@pytest.mark.parametrize(
    "example",
    [
        "fernet",
        "cc",
        "getattr",
        "comment",
    ],
)
def test_simple_cases(deobfuscate_example, example):
    """Test 1-2 rules per example"""
    deobfuscate_example(example, "simple")

@pytest.mark.skip(reason="TODO: Fix the rule")
@pytest.mark.parametrize(
    "example",
    [
        "getattr",
    ]
)
def test_mixed_cases(deobfuscate_example, example):
    """Mix a few rules to check if they don't interfere"""
    deobfuscate_example(example, "mixed")


# TODO: Tests based on real cases

