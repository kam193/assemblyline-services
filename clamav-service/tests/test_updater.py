import logging
import shutil
import subprocess

from assemblyline.odm.models.service import UpdateSource
from service.updater import ClamavServiceUpdater


class _FakeUpdater:
    """Stand-in for `self`: _prepare_configs only touches `self.log`, so a full
    ClamavServiceUpdater isn't needed."""

    log = logging.getLogger("test.clamav_updater")


def _read_conf(update_dir) -> str:
    return (update_dir / "freshclam.conf").read_text()


def _assert_accepted_by_clamconf(config_dir) -> None:
    """clamconf parses the config files in `config_dir` and reports any
    unrecognized/invalid directive on stderr."""
    if shutil.which("clamconf") is None:
        return

    (config_dir / "freshclam.conf").chmod(0o644)
    result = subprocess.run(
        ["clamconf", "--config-dir", str(config_dir)],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert "Parse error" not in result.stderr, result.stderr


class TestClamavServiceUpdaterPrepareConfigs:
    def test_configuration_based_source_writes_directives_and_default_mirror(self, tmp_path):
        source = UpdateSource(
            {
                "name": "freshclam",
                "uri": "database.clamav.net",
                "configuration": {"DNSDatabaseInfo": "current.cvd.clamav.net"},
            }
        )

        ClamavServiceUpdater._prepare_configs(_FakeUpdater(), str(tmp_path), source)

        conf = _read_conf(tmp_path)
        assert f"DatabaseDirectory {tmp_path}" in conf
        assert "DNSDatabaseInfo current.cvd.clamav.net" in conf
        assert "DatabaseMirror database.clamav.net" in conf
        _assert_accepted_by_clamconf(tmp_path)

    def test_explicit_database_mirror_suppresses_default_mirror(self, tmp_path):
        source = UpdateSource(
            {
                "name": "custom",
                "uri": "http://example.invalid/",
                "configuration": {"DatabaseMirror": "http://mirror.example.invalid/"},
            }
        )

        ClamavServiceUpdater._prepare_configs(_FakeUpdater(), str(tmp_path), source)

        conf = _read_conf(tmp_path)
        assert "DatabaseMirror http://mirror.example.invalid/" in conf
        assert "DatabaseMirror http://example.invalid/" not in conf
        _assert_accepted_by_clamconf(tmp_path)

    def test_legacy_header_based_source_is_still_supported(self, tmp_path):
        source = UpdateSource(
            {
                "name": "legacy",
                "uri": "http://legacy.example.invalid/",
                "headers": [
                    {"name": "DatabaseMirror", "value": "http://legacy-mirror.example.invalid/"}
                ],
            }
        )

        ClamavServiceUpdater._prepare_configs(_FakeUpdater(), str(tmp_path), source)

        conf = _read_conf(tmp_path)
        assert "DatabaseMirror http://legacy-mirror.example.invalid/" in conf
        assert "DatabaseMirror http://legacy.example.invalid/" not in conf
        _assert_accepted_by_clamconf(tmp_path)

    def test_underscore_prefixed_legacy_headers_are_returned_not_written(self, tmp_path):
        source = UpdateSource(
            {
                "name": "legacy",
                "uri": "http://legacy.example.invalid/",
                "headers": [{"name": "_InternalOption", "value": "hidden"}],
            }
        )

        service_configs = ClamavServiceUpdater._prepare_configs(
            _FakeUpdater(), str(tmp_path), source
        )

        conf = _read_conf(tmp_path)
        assert "_InternalOption" not in conf
        assert service_configs == {"_InternalOption": "hidden"}
        _assert_accepted_by_clamconf(tmp_path)
