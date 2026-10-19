import os
import json
import pytest
from pathlib import Path
from antigravity import parse_antigravity


@pytest.mark.integration
@pytest.mark.slow
class TestDatasetTarballIntegration:
    """Integration tests running parse_antigravity across real-world datasets in dataset.tar.gz."""

    def test_dataset_extracted_successfully(self, dataset_root):
        assert dataset_root.is_dir()
        gemini_dirs = sorted(list(dataset_root.glob(".gemini_*")))
        assert len(gemini_dirs) == 9, f"Expected 9 .gemini_* directories, found {len(gemini_dirs)}"

    @pytest.mark.parametrize("folder_name", [
        ".gemini_original",
        ".gemini_trigger1",
        ".gemini_trigger2",
        ".gemini_trigger3",
        ".gemini_trigger4",
        ".gemini_trigger5",
        ".gemini_trigger6",
        ".gemini_trigger7",
        ".gemini_trigger8",
    ])
    def test_parse_real_datasets(self, dataset_root, folder_name):
        target_dir = dataset_root / folder_name
        agy_cli_dir = target_dir / "antigravity-cli" if (target_dir / "antigravity-cli").is_dir() else target_dir

        result = parse_antigravity(str(agy_cli_dir))

        # Basic metadata
        assert result["contract_version"] == "actf-parser-result-v1"
        assert result["agent"] == "antigravity"
        assert len(result["errors"]) == 0, f"Parser encountered errors in {folder_name}: {result['errors']}"

        # Sessions validation
        sessions = result["sessions"]
        assert len(sessions) > 0, f"No sessions extracted for {folder_name}"
        for s in sessions:
            assert "session_id" in s
            assert "created_at" in s
            assert "updated_at" in s
            assert "event_ids" in s
            assert len(s["event_ids"]) > 0

        # Events validation
        events = result["events"]
        assert len(events) > 0, f"No events extracted for {folder_name}"
        session_event_ids = {e["event_id"] for e in events}
        for s in sessions:
            for eid in s["event_ids"]:
                assert eid in session_event_ids, f"Event {eid} in session not found in events list"

        # Forensic metadata
        assert "forensic" in result
        assert "tampered" in result["forensic"]
        assert "discrepancies" in result["forensic"]

        # Source inventory
        inv = result["source_inventory"]
        assert len(inv["transcript_full"]) > 0
        assert len(inv["history"]) > 0
