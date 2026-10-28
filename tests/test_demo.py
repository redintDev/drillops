"""Integration tests for Interactive Demo and Onboarding Engine."""

import os
import tempfile
import zipfile
import pytest

from drillops.demo.interactive import InteractiveDemoRunner


def test_interactive_demo_lifecycle():
    with tempfile.TemporaryDirectory() as tmpdir:
        demo_runner = InteractiveDemoRunner()
        res = demo_runner.run_demo(output_dir=tmpdir)

        assert res["valid_status"] == "PASSED"
        assert res["corrupt_status"] == "FAILED"
        assert res["valid_certificate_id"].startswith("DRC-")
        assert res["corrupt_certificate_id"].startswith("DRC-")

        # Verify audit pack zip was generated and valid
        audit_zip = res["audit_pack_path"]
        assert os.path.isfile(audit_zip)
        with zipfile.ZipFile(audit_zip, "r") as zf:
            files = zf.namelist()
            assert "AUDIT_DOSSIER.md" in files
            assert "AUDIT_DOSSIER.html" in files
            assert "manifest.json" in files
