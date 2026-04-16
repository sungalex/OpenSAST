"""pipeline.py 2nd pass 조건 테스트 — v0.4.2 회귀 방지."""

from unittest.mock import MagicMock, patch

from aisast.orchestrator.pipeline import ScanOptions, ScanPipeline


class TestSecondPassCondition:
    """사용자가 엔진을 지정해도 2nd pass 엔진이 포함되면 실행해야 함."""

    @patch("aisast.orchestrator.pipeline.build_engine")
    @patch("aisast.orchestrator.pipeline.emit_hook", return_value=[])
    def test_custom_engines_with_codeql_runs_second_pass(self, _hook, mock_build):
        """engines=("opengrep", "codeql") → codeql이 2nd pass에서 실행."""
        mock_engine = MagicMock()
        mock_engine.run.return_value = MagicMock(findings=[], duration_seconds=0.1)
        mock_build.return_value = mock_engine

        pipeline = ScanPipeline()
        options = ScanOptions(engines=("opengrep", "codeql"))

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            pipeline.scan(Path(tmp), options=options)

        built = [call.args[0] for call in mock_build.call_args_list]
        assert "codeql" in built, "codeql이 빌드되어야 함"

    @patch("aisast.orchestrator.pipeline.build_engine")
    @patch("aisast.orchestrator.pipeline.emit_hook", return_value=[])
    def test_custom_engines_without_second_pass_skips(self, _hook, mock_build):
        """engines=("opengrep", "bandit") → 2nd pass 엔진 없으므로 건너뜀."""
        mock_engine = MagicMock()
        mock_engine.run.return_value = MagicMock(findings=[], duration_seconds=0.1)
        mock_build.return_value = mock_engine

        pipeline = ScanPipeline()
        options = ScanOptions(engines=("opengrep", "bandit"))

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            pipeline.scan(Path(tmp), options=options)

        built = [call.args[0] for call in mock_build.call_args_list]
        assert "codeql" not in built
        assert "spotbugs" not in built

    @patch("aisast.orchestrator.pipeline.build_engine")
    @patch("aisast.orchestrator.pipeline.emit_hook", return_value=[])
    def test_default_engines_runs_both_passes(self, _hook, mock_build):
        """기본 엔진 → 1st + 2nd pass 모두 실행."""
        mock_engine = MagicMock()
        mock_engine.run.return_value = MagicMock(findings=[], duration_seconds=0.1)
        mock_build.return_value = mock_engine

        pipeline = ScanPipeline()

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            pipeline.scan(Path(tmp))

        built = [call.args[0] for call in mock_build.call_args_list]
        assert "opengrep" in built
        assert "codeql" in built

    @patch("aisast.orchestrator.pipeline.build_engine")
    @patch("aisast.orchestrator.pipeline.emit_hook", return_value=[])
    def test_disable_second_pass(self, _hook, mock_build):
        """enable_second_pass=False → 2nd pass 무시."""
        mock_engine = MagicMock()
        mock_engine.run.return_value = MagicMock(findings=[], duration_seconds=0.1)
        mock_build.return_value = mock_engine

        pipeline = ScanPipeline()
        options = ScanOptions(enable_second_pass=False)

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            pipeline.scan(Path(tmp), options=options)

        built = [call.args[0] for call in mock_build.call_args_list]
        assert "codeql" not in built
        assert "spotbugs" not in built
