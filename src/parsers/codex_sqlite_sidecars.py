"""수집한 Codex 증거의 SQLite WAL/SHM 교차 확인 (읽기 전용).

SHM(wal-index)에는 대화 본문이나 SQLite 레코드 내용이 전혀 없다.
기록된 메타데이터로 어떤 WAL 세대/페이지-프레임 색인을 관측했는지만 뒷받침할 수 있다.
SHM을 근거로 대화가 삭제됐거나 메시지가 전송됐다고 판단해서는 안 된다.
https://sqlite.org/walformat.html
"""
from __future__ import annotations

from pathlib import Path


WAL_INDEX_VERSION = 3007000


# 지정 위치의 4바이트를 부호 없는 정수로 읽는다
def _u32(blob: bytes, offset: int, endian: str) -> int:
    return int.from_bytes(blob[offset:offset+4], endian)


# wal-index 헤더 체크섬 계산 (SQLite WAL 체크섬 알고리즘)
def _checksum(blob: bytes, endian: str) -> tuple[int, int]:
    if len(blob) % 8:
        raise ValueError("invalid wal-index checksum byte count")
    s1 = s2 = 0
    for i in range(0, len(blob), 8):
        x = _u32(blob, i, endian)
        y = _u32(blob, i+4, endian)
        s1 = (s1 + x + s2) & 0xffffffff
        s2 = (s2 + y + s1) & 0xffffffff
    return s1, s2


# SHM 헤더(48바이트)를 해석 -- 버전·체크섬·페이지 크기가 맞는 바이트 순서를 찾아 값을 돌려준다
def _decode_shm_header(blob: bytes, off: int) -> dict | None:
    if len(blob) < off+48:
        return None
    header = blob[off:off+48]
    for endian in ("little", "big"):
        if _u32(header, 0, endian) != WAL_INDEX_VERSION:
            continue
        # 공유 메모리에서는 체크섬 값이 기기 고유 바이트 순서로 저장된다.
        observed = (_u32(header, 40, endian), _u32(header, 44, endian))
        if _checksum(header[:40], endian) != observed:
            continue
        ps = int.from_bytes(header[14:16], endian)
        ps = 65536 if ps == 1 else ps
        if not (512 <= ps <= 65536 and ps & (ps-1) == 0):
            continue
        return {
            "header_checksum_valid": True, "native_endian": endian,
            "change_counter": _u32(header, 8, endian),
            "initialized": header[12] == 1,
            "big_endian_wal_checksum": bool(header[13]),
            "page_size": ps,
            "committed_max_frame": _u32(header, 16, endian),
            "database_pages": _u32(header, 20, endian),
            "last_frame_checksum": header[24:32].hex(),
            "salt_hex": header[32:40].hex(),
            "raw_header": header,
        }
    return None


def _shm_page_index(blob: bytes, frame: int, endian: str) -> int | None:
    """1부터 시작하는 WAL 프레임 번호를 aPgno[] 위치로 변환해 DB 페이지 번호를 읽는다 (SHM 해시 슬롯이 아님)."""
    if frame < 1:
        return None
    zero_index = frame - 1
    if zero_index < 4062:
        offset = 136 + zero_index * 4
    else:
        tail = zero_index-4062
        offset = 32768 + tail // 4096 * 32768 + (tail % 4096) * 4
    if offset + 4 > len(blob):
        return None
    return _u32(blob, offset, endian)


def inspect_shm(shm: Path, wal: Path | None = None, frames: list[dict] | None = None) -> dict:
    """수집한 WAL 색인(SHM)을 검사하고, 체크섬으로 따로 검증한 WAL 프레임과 대조한다.

    SHM이 맞지 않거나 오래됐거나 없어도, 따로 검증된 WAL 프레임 증거를 무효로 만들지 않는다.
    SHM은 항상 휘발성 메타데이터로만 취급한다.
    """
    result = {
        "shm_path": str(shm), "shm_exists": shm.is_file(),
        "shm_contains_conversation_content": False,
        "shm_status": "NOT_ACQUIRED", "shm_header_valid": False,
        "frame_page_checks": 0, "frame_page_mismatches": 0,
        "warning": "SHM is volatile metadata, never a source of deleted messages.",
    }
    if not shm.is_file():
        return result
    blob = shm.read_bytes()
    result["shm_bytes"] = len(blob)
    if len(blob) < 136 or len(blob) % 32768:
        result["shm_status"] = "MALFORMED_OR_TRUNCATED"
        return result
    a, b = _decode_shm_header(blob, 0), _decode_shm_header(blob, 48)
    if not a or not b:
        result["shm_status"] = "INVALID_OR_TORN_HEADER"
        return result
    result["shm_header_valid"] = True
    result["shm_header_copies_equal"] = a["raw_header"] == b["raw_header"]
    if not result["shm_header_copies_equal"] or not a["initialized"]:
        result["shm_status"] = "INCONSISTENT_HEADER_COPIES"
        return result
    endian = a["native_endian"]
    mx = a["committed_max_frame"]
    backfill = _u32(blob, 96, endian)
    result.update({
        "shm_native_endian": endian, "shm_page_size": a["page_size"],
        "shm_mx_frame": mx, "shm_backfilled_frames": backfill,
        "shm_change_counter": a["change_counter"],
        "shm_salt_hex": a["salt_hex"],
        "shm_database_pages": a["database_pages"],
    })
    if wal is None or not wal.is_file() or frames is None:
        result["shm_status"] = "VALID_SHM_WAL_UNAVAILABLE"
        return result
    with wal.open("rb") as fd:
        wal_header = fd.read(32)
    if len(wal_header) < 32 or wal_header[16:24].hex() != a["salt_hex"]:
        result["shm_status"] = "SHM_WAL_GENERATION_MISMATCH"
        return result
    ps = int.from_bytes(wal_header[8:12], "big") or 65536
    wal_big = int.from_bytes(wal_header[:4], "big") == 0x377f0683
    result["wal_checksum_valid_frames"] = len(frames)
    if ps != a["page_size"] or wal_big != a["big_endian_wal_checksum"]:
        result["shm_status"] = "SHM_WAL_HEADER_MISMATCH"
        return result
    if mx > len(frames):
        result["shm_status"] = "SHM_MXFRAME_BEYOND_VALID_WAL"
        return result
    # mxFrame은 마지막으로 커밋된 프레임이며, 수집한 WAL의 끝과 같을 필요는 없다.
    # 커밋되지 않은 추가 프레임을 손상으로 해석하지 않는다.
    if mx and not frames[mx-1]["committed_here"]:
        result["shm_status"] = "SHM_MXFRAME_HAS_NO_WAL_COMMIT_MARKER"
        return result
    if backfill > mx:
        result["shm_status"] = "SHM_CHECKPOINT_COUNTER_MISMATCH"
        return result
    for f in frames[:mx]:
        page_index = _shm_page_index(blob, f["frame"], endian)
        if page_index is None:
            result["shm_status"] = "SHM_FRAME_INDEX_TRUNCATED"
            return result
        result["frame_page_checks"] += 1
        if page_index != f["db_page"]:
            result["frame_page_mismatches"] += 1
    if result["frame_page_mismatches"]:
        result["shm_status"] = "SHM_FRAME_INDEX_MISMATCH"
    else:
        result["shm_status"] = "CONSISTENT_WITH_ACQUIRED_WAL"
    return result
