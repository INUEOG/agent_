import os
from pathlib import Path
import pytest
from antigravity import parse_antigravity, _antigravity_conversation_ids

LOCAL_AGY_DATA = Path("~/temp/AGY_TEST_DATA").expanduser()


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.skipif(
    not LOCAL_AGY_DATA.is_dir(),
    reason=f"Local AGY_TEST_DATA directory not found at {LOCAL_AGY_DATA}"
)
class TestLocalAgyDataset:
    """Automated integration tests validating the local AGY_TEST_DATA dataset."""

    def test_conversation_discovery(self):
        cids = _antigravity_conversation_ids(str(LOCAL_AGY_DATA))
        assert len(cids) == 50, f"Expected 50 conversations in AGY_TEST_DATA, found {len(cids)}"

        # Validate that known conversation IDs are present
        expected_ids = [
                "6aeed1da-e877-4f47-a9e8-5e75ff74350e",
                "65382cbe-a3ba-42f1-b465-e7c10251a05d",
                "00fbd146-8a39-4cfd-afcf-a1156db6a2bc",
                "69569d09-1b6c-4569-86d0-d913e3fc70d8",
                "193cc801-044a-45c5-8ce7-6b6330e39e99",
                "8e2a5995-1390-409f-ba16-d5da92a4b624",
                "8c1710ca-385d-4046-9d89-d335d34ff1b8",
                "34c95303-1ef5-4a9c-8d89-2f7c760b7ea8",
                "05545309-88d1-4d03-aca3-2d1da058a5db",
                "a5be7233-2acf-4e2f-bfa0-4b1b1cbd6b62",
                "5b61b637-a3b9-47f8-90c9-1a720853f06a",
                "0c757988-d606-4b06-aacb-d1998113e5c8",
                "25db10e6-b175-4d8b-9d34-8bcd3e482dae",
                "b50987fe-b357-482f-a8a9-4ca317cb84c8",
                "ca61e25c-6717-4208-b1e8-6390cd10eaeb",
                "86ee5f1c-efd2-4f6a-a41c-3d8d19e1332a",
                "30ada22f-4c08-49bf-a4b2-57012186f310",
                "d2f3fbcc-d697-4194-9162-5bacba3d72cb",
                "c5188ae0-cc46-448b-80c9-9cab96419a58",
                "804e1099-4e37-468f-b9b7-8ee34262df23",
                "0a58bc10-b496-401d-97cd-b128092d2423",
                "1e287fd9-66a6-4624-9ba2-612912087a92",
                "fae29dc5-ba6b-40fc-b825-c13ea8d087ab",
                "476bb272-667a-4a63-92a1-1d12250bd0d0",
                "30c154e0-5638-42e1-9039-7bf70874942e",
                "f2c7bfe2-dba9-4337-a89b-2a1853f8010a",
                "1abe5846-3f21-450a-b895-f8a4ea9ddacf",
                "f2a2efdb-423b-41db-8810-b957636e833b",
                "81e40e5f-c1c1-4e9e-bd60-4743f510e04a",
                "f80d7826-2f6a-4a39-be41-35dcda88f36f",
                "09614335-cfcc-4f3c-9387-c0e615da22ca",
                "325d51ab-05ed-4148-818a-35f634a17d2a",
                "fbff1026-eef1-45fd-935e-cd4f0f1e01d7",
                "6dfb4594-4f35-4988-a4d4-e602f7ddfec2",
                "73e4e058-4750-4e06-bd13-30a65688c7a8",
                "cbca547f-d73b-4d7a-b310-f8160e98b25e",
                "72a6fd7f-cd36-4fbd-af94-514c319a271c",
                "458c1f82-d797-4a33-bbeb-3134a3de96e7",
                "30f6b62f-495e-4d7c-abb9-aec5892250a6",
                "6824fd29-61f0-4eba-ab7c-808d6eb4d3cc",
                "4ef2f6ee-51a1-470a-ab21-b88ddf6f3ab8",
                "9e41988a-e4f7-4288-8976-a8499229bc14",
                "612662c2-26a4-4429-8d70-c38e6cdedf75",
                "15ae3577-5481-4d8c-a5eb-3ec7232ced2a",
                "aa185b98-706f-4ad5-acd3-ca33e05d0224",
                "f3c67795-dbf8-4696-bd27-e1b2414b3961",
                "0845b543-639f-4a5b-8bec-632b4c79b346",
                "2f0d84db-672b-4170-9d78-c6e611202a08",
                "32216d26-fb86-4d94-8c5b-b31828a45292",
                "8c79fe02-9e07-4fd9-bcea-f24fb8b56af3",
                "2f0d84db-672b-4170-9d78-c6e611202a08",
                "aa185b98-706f-4ad5-acd3-ca33e05d0224",
                "15ae3577-5481-4d8c-a5eb-3ec7232ced2a",
                "6824fd29-61f0-4eba-ab7c-808d6eb4d3cc",
                "cbca547f-d73b-4d7a-b310-f8160e98b25e"
        ]
        for cid in expected_ids:
            assert cid in cids, f"Expected conversation {cid} to be discovered"

    def test_parse_single_conversation(self):
        target_cid = "65382cbe-a3ba-42f1-b465-e7c10251a05d"
        result = parse_antigravity(str(LOCAL_AGY_DATA), conversation_id=target_cid)

        assert len(result["errors"]) == 0
        assert len(result["sessions"]) == 1
        assert result["sessions"][0]["session_id"] == target_cid
        assert len(result["events"]) == 2197

        # Validate event reference integrity
        session_event_ids = set(result["sessions"][0]["event_ids"])
        event_ids = {e["event_id"] for e in result["events"]}
        assert session_event_ids.issubset(event_ids)

    def test_parse_full_local_dataset(self, local_dataset_result):
        result = local_dataset_result

        # Overall metadata
        assert result["contract_version"] == "actf-parser-result-v1"
        assert result["agent"] == "antigravity"
        assert len(result["errors"]) == 0, f"Encountered unexpected parser errors: {result['errors']}"

        # Quantitative integrity
        assert len(result["sessions"]) == 50
        assert len(result["events"]) == 3803

        # Forensic discrepancy detection
        assert result["forensic"]["tampered"] is False
        assert len(result["forensic"]["discrepancies"]) == 0

        # Source inventory completeness
        inv = result["source_inventory"]
        assert len(inv["transcript_full"]) == 48
        assert len(inv["history"]) == 1
        assert len(inv["conversations_db"]) > 0
        assert len(inv["conversation_summaries_db"]) == 1
