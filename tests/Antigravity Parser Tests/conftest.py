import os
import sys
import json
import sqlite3
import tarfile
import tempfile
from pathlib import Path
import pytest

# Ensure src and src/parsers are always importable
CURRENT_TEST_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_TEST_DIR.parent.parent
SRC_DIR = REPO_ROOT / "src"
PARSERS_DIR = SRC_DIR / "parsers"

for p in [str(REPO_ROOT), str(SRC_DIR), str(PARSERS_DIR), str(CURRENT_TEST_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)


@pytest.fixture(scope="session")
def dataset_root():
    """Extracts dataset/dataset.tar.gz once for the session and yields the path."""
    tar_path = CURRENT_TEST_DIR / "dataset" / "dataset.tar.gz"
    if not tar_path.is_file():
        tar_path = REPO_ROOT / "tests" / "dataset" / "dataset.tar.gz"
    if not tar_path.is_file():
        pytest.skip(f"Dataset tar not found at {tar_path}")

    temp_dir = tempfile.TemporaryDirectory(prefix="agy_test_dataset_")
    with tarfile.open(tar_path, "r:gz") as tar:
        tar.extractall(path=temp_dir.name)

    extracted_dir = Path(temp_dir.name) / "create_test"
    yield extracted_dir
    temp_dir.cleanup()


LOCAL_AGY_DATA = Path("~/temp/AGY_TEST_DATA").expanduser()


@pytest.fixture(scope="session")
def local_dataset_result():
    """Parses AGY_TEST_DATA once for the entire test session and shares the result."""
    if not LOCAL_AGY_DATA.is_dir():
        pytest.skip(f"Local AGY_TEST_DATA directory not found at {LOCAL_AGY_DATA}")
    from antigravity import parse_antigravity
    return parse_antigravity(str(LOCAL_AGY_DATA))



@pytest.fixture
def mock_antigravity_cli(tmp_path):
    """Creates a minimal synthetic antigravity-cli workspace for fast isolated testing."""
    root = tmp_path / "antigravity-cli"
    root.mkdir()

    # settings.json
    settings_file = root / "settings.json"
    settings_data = {
        "permissions": {
            "allow": [
                "command(ls)",
                "command(git status)",
                "command(python3 script.py)"
            ]
        }
    }
    settings_file.write_text(json.dumps(settings_data, indent=2), encoding="utf-8")

    # history.jsonl
    history_file = root / "history.jsonl"
    hist_entries = [
        {
            "conversationId": "test-session-001",
            "display": "run python test",
            "type": "user_input",
            "timestamp": 1726826400000
        },
        {
            "conversationId": "test-session-001",
            "display": "python3 script.py",
            "type": "shell",
            "timestamp": 1726826405000
        }
    ]
    with open(history_file, "w", encoding="utf-8") as f:
        for entry in hist_entries:
            f.write(json.dumps(entry) + "\n")

    # brain / test-session-001
    brain_dir = root / "brain" / "test-session-001"
    logs_dir = brain_dir / ".system_generated" / "logs"
    logs_dir.mkdir(parents=True)

    transcript_full = logs_dir / "transcript_full.jsonl"
    steps = [
        {
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2024-09-20T10:00:00.001Z",
            "content": "<USER_REQUEST>\nrun python test\n</USER_REQUEST><ADDITIONAL_METADATA>\nThe current local time is: 2024-09-20T19:00:00+09:00.\n</ADDITIONAL_METADATA>",
            "status": "DONE"
        },
        {
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2024-09-20T10:00:02.000Z",
            "content": "Executing python script.",
            "tool_calls": [
                {
                    "name": "run_command",
                    "args": {"CommandLine": "python3 script.py", "Cwd": "/home/user/project"}
                }
            ],
            "status": "DONE"
        }
    ]
    with open(transcript_full, "w", encoding="utf-8") as f:
        for s in steps:
            f.write(json.dumps(s) + "\n")

    # transcript.jsonl
    transcript_compact = logs_dir / "transcript.jsonl"
    with open(transcript_compact, "w", encoding="utf-8") as f:
        for s in steps:
            f.write(json.dumps(s) + "\n")

    # conversations/test-session-001.db
    convs_dir = root / "conversations"
    convs_dir.mkdir()
    db_path = convs_dir / "test-session-001.db"
    conn = sqlite3.connect(str(db_path))
    c = conn.cursor()
    c.execute("CREATE TABLE steps (idx INTEGER PRIMARY KEY, step_payload BLOB, step_type TEXT)")
    c.execute("INSERT INTO steps (idx, step_payload, step_type) VALUES (?, ?, ?)", (0, b"prefix:run python test:suffix", "USER_INPUT"))
    c.execute("INSERT INTO steps (idx, step_payload, step_type) VALUES (?, ?, ?)", (1, b"Executing python script.", "MODEL"))
    conn.commit()
    conn.close()

    # conversation_summaries.db
    sum_db = root / "conversation_summaries.db"
    conn = sqlite3.connect(str(sum_db))
    c = conn.cursor()
    c.execute("CREATE TABLE conversation_summaries (conversation_id TEXT PRIMARY KEY, step_count INTEGER, parent_conversation_id TEXT, last_modified_time TEXT)")
    c.execute("INSERT INTO conversation_summaries VALUES (?, ?, ?, ?)", ("test-session-001", 2, None, "2024-09-20T10:00:05.000Z"))
    conn.commit()
    conn.close()

    return root
