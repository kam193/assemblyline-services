import shutil

import pytest

from tests.al import build_request, eicar_bytes, write_hdb_signature

pytestmark = [
    pytest.mark.clamd,
    pytest.mark.skipif(shutil.which("clamd") is None, reason="clamd binary not installed"),
]


class TestClamAVService:
    def test_scan_benign_file_reports_no_match(self, clamav_service, tmp_path):
        benign = tmp_path / "benign.txt"
        benign.write_text("just a harmless test file\n")

        request = build_request(str(benign))
        clamav_service.execute(request)

        assert request.result.sections == []

    def test_reload_rules_detects_newly_added_signature(self, clamav_service, tmp_path):
        content = eicar_bytes()
        sample = tmp_path / "sample.bin"
        sample.write_bytes(content)
        request = build_request(str(sample))

        # Started with only the placeholder signature - nothing should match yet.
        clamav_service.execute(request)
        assert request.result.sections == []

        # Simulate the updater delivering a new ruleset and reload, without
        # restarting the daemon.
        staged_source = tmp_path / "staged" / "test-source"
        staged_source.mkdir(parents=True)
        write_hdb_signature(str(staged_source), content, "Test-Eicar-Custom")
        clamav_service.rules_directory = str(tmp_path / "staged")
        clamav_service._load_rules()

        clamav_service.execute(request)

        sections = request.result.sections
        assert len(sections) == 1
        assert sections[0].title_text == "Matched malicious signatures"
        assert sections[0].heuristic.heur_id == 1
        # clamd appends .UNOFFICIAL to signatures from local, unsigned databases.
        assert sections[0].tags["av.virus_name"] == ["Test-Eicar-Custom.UNOFFICIAL"]
