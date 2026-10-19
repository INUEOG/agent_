"""Known-open rule problems, pinned as strict xfail.

Each test states the DESIRED behaviour.  It fails today (xfail).  When the rule
is fixed the test starts passing, ``strict=True`` turns that into a failure, and
the fixer removes the marker (and regenerates tests/baseline/golden_output.json
after reviewing the diff).  Each reason names the module where the fix belongs.
"""
import pytest

from investigation import build_investigation_result


def _card(result, value):
    return next(c for c in result["candidates"] if c["entity"]["value"] == value)


@pytest.mark.xfail(strict=True, reason="observations.py: missing collection_status defaults to 'observed' (rule:observation-contract)")
def test_observation_without_status_is_not_observed():
    result = build_investigation_result([], [
        {"observation_type": "network_connection", "source": "network_sensor", "source_ref": "n:1", "remote_host": "nostatus.test"},
    ])
    cards = [c for c in result["candidates"] if c["entity"]["value"] == "nostatus.test"]
    assert not cards or cards[0]["evidence_level"] != "observed" or result["errors"]


@pytest.mark.xfail(strict=True, reason="observations.py: unknown source and empty source_ref are accepted as observed evidence (rule:observation-contract)")
def test_observation_without_source_and_ref_is_not_observed():
    result = build_investigation_result([], [
        {"observation_type": "network_connection", "collection_status": "observed", "remote_host": "noref.test"},
    ])
    cards = [c for c in result["candidates"] if c["entity"]["value"] == "noref.test"]
    assert not cards or cards[0]["evidence_level"] != "observed" or result["errors"]


@pytest.mark.xfail(strict=True, reason="graph.py/scoring.py: event-level correlation leaks to other targets of the same event (rule:entity-level-correlation)")
def test_correlation_does_not_leak_to_other_targets():
    events = [{"event_id": "e1", "event_type": "command_execution", "tags": ["command_request"],
               "command": "curl https://a.test && curl https://b.test"}]
    obs = [{"observation_id": "o1", "observation_type": "network_connection", "collection_status": "observed",
            "source": "network_sensor", "source_ref": "n:1", "remote_host": "a.test", "related_event_id": "e1"}]
    result = build_investigation_result(events, obs)
    assert _card(result, "a.test")["discovery_path"]["directly_correlated_event_ids"] == ["e1"]
    assert _card(result, "b.test")["discovery_path"]["directly_correlated_event_ids"] == []


@pytest.mark.xfail(strict=True, reason="extraction.py: file names are extracted as domains (rule:filename-false-positive)")
def test_file_names_are_not_domains():
    events = [{"event_id": "e1", "event_type": "command_execution", "tags": ["command_request"],
               "command": "python main.py --config config.json && cat README.md && curl https://api-lab.test/"}]
    domains = {c["entity"]["value"] for c in build_investigation_result(events)["candidates"] if c["entity"]["entity_type"] == "domain"}
    assert "api-lab.test" in domains
    assert not domains & {"main.py", "config.json", "readme.md"}
