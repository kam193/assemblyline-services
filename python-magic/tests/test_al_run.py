import pytest

from tests.al import build_request

from .conftest import SAMPLE1_SDIST, SAMPLE1_WHEEL


@pytest.fixture
def make_service(tmp_path):
    def _make(blocklist=None):
        from service.al_run import AssemblylineService

        svc = AssemblylineService({})
        svc.start()
        if blocklist:
            for source, names in blocklist.items():
                source_dir = tmp_path / "rules" / source
                source_dir.mkdir(parents=True)
                (source_dir / "list.txt").write_text("\n".join(names))
            svc.rules_directory = str(tmp_path / "rules")
            svc._load_rules()
        return svc

    return _make


def heuristic_ids(sections):
    ids = set()
    for section in sections:
        if section.heuristic:
            ids.add(section.heuristic.heur_id)
        ids |= heuristic_ids(section.subsections)
    return ids


class TestAssemblylineService:
    @pytest.mark.parametrize("path", [SAMPLE1_SDIST, SAMPLE1_WHEEL])
    def test_blocklisted_requirement_is_reported(self, make_service, path):
        request = build_request(path)

        make_service({"malicious_list": ["requests"]}).execute(request)

        assert heuristic_ids(request.result.sections) == {1}

    @pytest.mark.parametrize("path", [SAMPLE1_SDIST, SAMPLE1_WHEEL])
    def test_package_without_blocklisted_requirement_is_clean(self, make_service, path):
        request = build_request(path)

        make_service({"malicious_list": ["not-used-anywhere"]}).execute(request)

        assert heuristic_ids(request.result.sections) == set()

    def test_non_python_archive_is_ignored(self, make_service, tmp_path):
        import zipfile

        path = tmp_path / "plain.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("readme.txt", "hello")
        request = build_request(str(path))

        make_service().execute(request)

        assert request.result.sections == []
