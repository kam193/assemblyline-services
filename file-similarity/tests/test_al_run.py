import random

import pytest
import tlsh

from tests.al import build_request

HEADER = "tlsh,file_type,reference,attribution.campaign,attribution.family,attribution.actor"


def random_bytes(seed, size=4000):
    return random.Random(seed).randbytes(size)


def mutate(data, count):
    data = bytearray(data)
    for i in range(count):
        data[i * 7] ^= 0xFF
    return bytes(data)


@pytest.fixture
def make_service(tmp_path):
    def _make(rows=(), config=None):
        from service.al_run import AssemblylineService

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir(exist_ok=True)
        (rules_dir / "list.csv").write_text("\n".join([HEADER, *rows]) + "\n")
        svc = AssemblylineService(config or {})
        svc.start()
        svc.rules_directory = str(rules_dir)
        svc._load_rules()
        return svc

    return _make


def csv_row(data, file_type="*", reference="https://example.com/ref", family="fam"):
    return f"{tlsh.hash(data)},{file_type},{reference},camp,{family},actor"


class TestAssemblylineService:
    def test_identical_file_has_high_similarity(self, make_service, sample_file):
        data = random_bytes(1)
        svc = make_service([csv_row(data)])
        request = build_request(sample_file(data))

        svc.execute(request)

        (section,) = request.result.sections
        assert section.title_text == "High similarity to potentially malicious files"
        assert section.heuristic.heur_id == 1
        assert section.tags["attribution.family"] == ["fam"]
        assert section.tags["attribution.actor"] == ["actor"]

    def test_slightly_modified_file_is_still_similar(self, make_service, sample_file):
        data = random_bytes(1)
        svc = make_service([csv_row(data)])
        request = build_request(sample_file(mutate(data, 40)))

        svc.execute(request)

        assert len(request.result.sections) == 1

    def test_unrelated_file_has_no_results(self, make_service, sample_file):
        svc = make_service([csv_row(random_bytes(1))])
        request = build_request(sample_file(random_bytes(2)))

        svc.execute(request)

        assert request.result.sections == []

    def test_too_small_file_has_no_results(self, make_service, sample_file):
        svc = make_service([csv_row(random_bytes(1))])
        request = build_request(sample_file(b"tiny"))

        svc.execute(request)

        assert request.result.sections == []

    def test_other_file_type_is_checked_only_in_deep_scan(self, make_service, sample_file):
        data = random_bytes(1)
        svc = make_service([csv_row(data, file_type="document/pdf")])

        normal = build_request(sample_file(data))
        svc.execute(normal)
        deep = build_request(sample_file(data))
        deep.task.deep_scan = True
        svc.execute(deep)

        assert normal.result.sections == []
        assert len(deep.result.sections) == 1
