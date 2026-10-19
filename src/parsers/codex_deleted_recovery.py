#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""범용 Codex SQLite 증거 복원 (읽기 전용 포렌식 사본 대상).

날짜나 스레드 ID를 고정하지 않고, 사용 가능한 SQLite DB를 조사해 가능한 경우
완전한 레코드와 현재 체크섬이 맞는 WAL 프레임을 검증한다. 일부 텍스트 조각은
절대 검증된 메시지로 올리지 않는다. 삭제된 원본 JSONL을 디스크에서 되살리는 카빙은
별도 디스크 이미지가 필요하므로 여기서는 하지 않는다.
"""
import argparse
import collections
import sys
import hashlib
import json
import re
import sqlite3
import struct
from collections import defaultdict
from bisect import bisect_right
from datetime import datetime, timezone
from pathlib import Path

try:
    from parsers.codex_sqlite_sidecars import inspect_shm
except ModuleNotFoundError:  # parser 폴더에서 단독 실행할 때의 import 경로
    from codex_sqlite_sidecars import inspect_shm

UUID = re.compile(r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
MARKER = "codex-writing-block-deleted-thread-v1:"
EXT = (".sqlite", ".sqlite3", ".db")


def v5_db_family(path):
    """수집한 Codex SQLite DB 파일의 종류를 판별한다 (번호 N을 고정하지 않음)."""
    name = path.name if isinstance(path, Path) else str(path)
    if name == 'codex-dev.db':
        return 'catalog'
    for family, prefix in [('state', 'state'), ('history', 'thread_history'), ('logs', 'logs')]:
        if re.fullmatch(rf'{prefix}_[0-9]+\.sqlite', name, re.I):
            return family
    return None


def v5_select_db(root, family):
    """src/parsers/codex.py와 같은 방식으로 가장 큰 번호의 세대 DB를 고른다."""
    if family == 'catalog':
        return root / 'sqlite' / 'codex-dev.db'
    prefix = {'state': 'state', 'history': 'thread_history', 'logs': 'logs'}[family]
    options = []
    for file in root.glob(f'{prefix}_*.sqlite'):
        m = re.fullmatch(rf'{prefix}_([0-9]+)\.sqlite', file.name, re.I)
        if file.is_file() and m:
            options.append((int(m.group(1)), file))
    return max(options, key=lambda x: x[0])[1] if options else root / f'{prefix}_unavailable.sqlite'


# Global 상태 JSON 안(중첩 JSON 문자열 포함)에서 삭제 표시 키(codex-writing-block-deleted-thread-v1:<ID>=true)의 스레드 ID를 모은다
def global_ids(obj, found, depth=0):
    if depth > 32:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and k.startswith(MARKER) and v is True:
                tid = k[len(MARKER):].lower()
                if UUID.fullmatch(tid):
                    found.add(tid)
            global_ids(v, found, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            global_ids(v, found, depth + 1)
    elif isinstance(obj, str) and obj.lstrip().startswith(("{", "[")):
        try:
            global_ids(json.loads(obj), found, depth + 1)
        except (ValueError, RecursionError):
            pass


# Global 상태 파일(JSON/.bak)에서 삭제 표시된 스레드 ID를 모은다 (파일 해시 출력)
def load_globals(root):
    result = set()
    for name in (".codex-global-state.json", ".codex-global-state.json.bak"):
        p = root / name
        if not p.is_file():
            print(f"[Global 없음] {p}")
            continue
        data = p.read_bytes()
        ids = set()
        global_ids(json.loads(data.decode("utf-8-sig")), ids)
        result |= ids
        print(f"[Global] {name}: 삭제 관련 표시 {len(ids)}개; sha256={hashlib.sha256(data).hexdigest()}")
    return result


# SQLite 가변 길이 정수(varint)를 읽어 (값, 사용 바이트 수)를 돌려준다
def uvar(b, off):
    val = 0
    for i in range(9):
        if off + i >= len(b):
            raise ValueError("incomplete varint")
        byte = b[off + i]
        if i == 8:
            return (val << 8) | byte, 9
        val = (val << 7) | (byte & 0x7f)
        if byte < 128:
            return val, i + 1
    raise ValueError("invalid varint")


# SQLite 레코드 페이로드(헤더+본문)를 컬럼 값 목록으로 해석
def record_values(payload):
    header, used = uvar(payload, 0)
    if not (used <= header <= len(payload)) or header > 2000:
        raise ValueError("bad record header")
    serials = []
    at = used
    while at < header:
        s, size = uvar(payload, at)
        at += size
        serials.append(s)
    if at != header or len(serials) > 128:
        raise ValueError("bad serial header")
    at = header
    values = []
    for s in serials:
        if s == 0:
            values.append(None)
            continue
        if s in (1, 2, 3, 4, 5, 6):
            length = {1:1, 2:2, 3:3, 4:4, 5:6, 6:8}[s]
            if at + length > len(payload):
                raise ValueError("truncated integer")
            values.append(int.from_bytes(payload[at:at+length], "big", signed=True))
            at += length
            continue
        if s == 7:
            if at + 8 > len(payload):
                raise ValueError("truncated float")
            values.append(struct.unpack_from(">d", payload, at)[0])
            at += 8
            continue
        if s in (8, 9):
            values.append(s - 8)
            continue
        if s in (10, 11):
            raise ValueError("reserved serial type")
        length = (s - 12) // 2
        if at + length > len(payload):
            raise ValueError("truncated text/blob")
        raw = payload[at:at+length]
        at += length
        values.append(raw.decode("utf-8") if s % 2 else raw)
    return values


# SQLite 파일 헤더에서 페이지 크기를 읽는다 (올바른 SQLite가 아니면 None)
def page_size(b):
    if len(b) < 100 or b[:16] != b"SQLite format 3\0":
        return None
    ps = int.from_bytes(b[16:18], "big")
    ps = 65536 if ps == 1 else ps
    if not (512 <= ps <= 65536 and (ps & (ps-1)) == 0):
        return None
    return ps


# 프리리스트(삭제되어 비워진 페이지 목록)의 트렁크/리프 페이지 번호를 모은다
def freelist_pages(b, ps):
    max_pages = len(b) // ps
    trunk = int.from_bytes(b[32:36], "big")
    trunks, leaves = set(), set()
    while 0 < trunk <= max_pages and trunk not in trunks:
        trunks.add(trunk)
        page = b[(trunk-1)*ps:trunk*ps]
        n = int.from_bytes(page[4:8], "big")
        if n > (ps-8)//4:
            break
        for i in range(n):
            p = int.from_bytes(page[8+4*i:12+4*i], "big")
            if 0 < p <= max_pages:
                leaves.add(p)
        trunk = int.from_bytes(page[:4], "big")
    return trunks, leaves-trunks


def leaf_cells_from_freelist(b, page_no, ps):
    """SQLite 테이블 B-트리 리프(0x0d) 페이지의 셀을 해석한다 (검증된 오버플로 체인 포함)."""
    page = b[(page_no-1)*ps:page_no*ps]
    hdr = 100 if page_no == 1 else 0
    if len(page) <= hdr + 8 or page[hdr] != 0x0d:
        return
    n = int.from_bytes(page[hdr+3:hdr+5], "big")
    if n > 4096 or hdr + 8 + 2*n > ps:
        return
    reserved = b[20]
    usable = ps - reserved
    max_local = usable - 35
    min_local = ((usable - 12) * 32 // 255) - 23
    total_pages = len(b) // ps
    for cell_i in range(n):
        cell = int.from_bytes(page[hdr+8+2*cell_i:hdr+10+2*cell_i], "big")
        if not (hdr+8 <= cell < usable):
            continue
        try:
            size, s1 = uvar(page, cell)
            rowid, s2 = uvar(page, cell+s1)
            start = cell+s1+s2
            if size > 16*1024*1024 or size < 0:
                continue
            local = size
            if size > max_local:
                local = min_local + (size-min_local) % (usable-4)
                if local > max_local:
                    local = min_local
            if local < 0 or start + local > usable:
                continue
            payload = page[start:start+local]
            visited = set()
            if size > local:
                if start + local + 4 > usable:
                    continue
                ov = int.from_bytes(page[start+local:start+local+4], "big")
                while len(payload) < size:
                    if not (0 < ov <= total_pages) or ov in visited:
                        raise ValueError("overflow chain broken")
                    visited.add(ov)
                    op = b[(ov-1)*ps:ov*ps]
                    ov = int.from_bytes(op[:4], "big")
                    payload += op[4:4 + min(usable-4, size-len(payload))]
            if len(payload) != size:
                continue
            yield rowid, cell_i, record_values(payload)
        except (ValueError, UnicodeDecodeError, IndexError, struct.error):
            continue


# 메인 DB를 immutable 모드로 연다 (WAL을 반영하지 않음)
def main_db_conn(p):
    # immutable=1: 복사한 메인 DB만 읽고 WAL은 무시한다.
    # WAL은 검증 전 후보 증거로 따로 조사한다.
    return sqlite3.connect(p.as_uri() + "?immutable=1", uri=True)


# 메인 DB의 살아 있는 테이블에서 대상 스레드 행을 읽는다 (thread_items / logs / threads)
def main_db_live_rows(path, targets):
    events = []
    try:
        db = main_db_conn(path)
    except sqlite3.DatabaseError:
        return events
    try:
        names = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        # SQL 실행 -- DB 오류가 나면 빈 결과
        def safe_fetch(sql):
            try:
                return db.execute(sql).fetchall()
            except sqlite3.DatabaseError:
                return []
        if v5_db_family(path) == "history":
            for table, fields in (("thread_items", "thread_id,turn_id,item_id,rollout_ordinal,created_at_ms,item_json,item_type,updated_at_ordinal"),
                                  ("thread_realtime_items", "thread_id,item_id,rollout_ordinal,created_at_ms,item_type,item_json")):
                if table not in names:
                    continue
                for row in safe_fetch(f"SELECT {fields} FROM {table}"):
                    if isinstance(row[0], str) and row[0].lower() in targets:
                        if table == "thread_items":
                            v = row
                        else:
                            v = (row[0], None, row[1], row[2], row[3], row[5], row[4], None)
                        event = interpret_row(path, "ACTIVE_MAIN_DB", "none", None, None, v, targets)
                        if event:
                            events.append(event)
        elif v5_db_family(path) == "logs" and "logs" in names:
            for row in safe_fetch("SELECT id,ts,ts_nanos,level,target,feedback_log_body,module_path,file,line,thread_id,process_uuid,estimated_bytes FROM logs"):
                if isinstance(row[9], str) and row[9].lower() in targets:
                    event = interpret_row(path, "ACTIVE_MAIN_DB", "none", None, row[0], row, targets)
                    if event:
                        events.append(event)
        elif v5_db_family(path) == "state" and "threads" in names:
            # 스키마 컬럼이 버전마다 달라서 PRAGMA로 이름을 매핑한다.
            cols = [x[1] for x in db.execute("PRAGMA table_info(threads)")]
            for row in safe_fetch("SELECT * FROM threads"):
                obj = dict(zip(cols, row))
                if isinstance(obj.get("id"), str) and obj["id"].lower() in targets:
                    events.append({"thread_id":obj["id"].lower(), "kind":"thread_metadata",
                                   "source":str(path), "method":"ACTIVE_MAIN_DB",
                                   "location":"live threads table", "timestamp":obj.get("created_at_ms") or obj.get("created_at"),
                                   "payload":{k:obj.get(k) for k in ("title", "first_user_message", "preview", "rollout_path", "cwd", "model")}})
    finally:
        db.close()
    return events


# DB 종류별 컬럼 구조에 맞춰 행 값을 복원 이벤트로 해석 (구조가 맞지 않으면 None)
def interpret_row(path, method, region, page, rowid, v, targets):
    where = f"page={page}, rowid={rowid}" if page is not None else f"rowid={rowid}"
    # thread_history_1.sqlite.thread_items: SQLite 컬럼 8개
    if v5_db_family(path) == "history" and len(v) == 8:
        tid, turn, itemid, ordinal, ts, rawjson, itemtype, _ = v
        if not (isinstance(tid, str) and UUID.fullmatch(tid) and (targets is None or tid.lower() in targets) and isinstance(rawjson, str)
                and isinstance(itemtype, str) and isinstance(itemid, str)):
            return None
        try:
            item = json.loads(rawjson)
        except ValueError:
            return None
        if not isinstance(item, dict) or item.get("type") != itemtype:
            return None
        return {"thread_id":tid.lower(), "kind":itemtype, "turn_id":turn, "item_id":itemid,
                "ordinal":ordinal, "timestamp":ts, "source":str(path), "method":method,
                "region":region, "location":where, "payload":item}
    # logs_2.sqlite.logs: 컬럼 12개
    if v5_db_family(path) == "logs" and len(v) == 12:
        tid = v[9]
        if not (isinstance(tid, str) and UUID.fullmatch(tid) and (targets is None or tid.lower() in targets) and isinstance(v[3],str)):
            return None
        return {"thread_id":tid.lower(), "kind":"runtime_log", "timestamp":v[1],
                "source":str(path), "method":method, "region":region, "location":where,
                "payload":{"level":v[3], "target":v[4], "feedback_log_body":v[5]}}
    # state_5.sqlite.threads: 관측 샘플에서 컬럼 40개 (버전에 따라 다를 수 있음)
    if v5_db_family(path) == "state" and len(v) >= 18:
        tid = v[0]
        if not (isinstance(tid, str) and UUID.fullmatch(tid) and (targets is None or tid.lower() in targets) and
                (v[1] is None or isinstance(v[1],str)) and isinstance(v[2], (int,type(None)))):
            return None
        return {"thread_id":tid.lower(), "kind":"thread_metadata", "timestamp":v[2],
                "source":str(path), "method":method, "region":region, "location":where,
                "payload":{"rollout_path":v[1], "created_at":v[2], "updated_at":v[3],
                           "cwd":v[6] if len(v)>6 else None, "title":v[7] if len(v)>7 else None,
                           "first_user_message":v[18] if len(v)>18 else None}}
    # codex-dev.db local_thread_catalog: 컬럼 17개
    if path.name == "codex-dev.db" and len(v) == 17:
        if not (isinstance(v[1],str) and UUID.fullmatch(v[1]) and (targets is None or v[1].lower() in targets)):
            return None
        return {"thread_id":v[1].lower(), "kind":"catalog_metadata", "timestamp":v[3],
                "source":str(path), "method":method, "region":region, "location":where,
                "payload":{"title":v[2], "cwd":v[5], "source":v[6]}}
    return None


# 프리리스트 리프 페이지의 셀을 해석해 대상 스레드의 삭제된 레코드를 찾는다
def main_db_freelist(path, targets):
    data = path.read_bytes()
    ps = page_size(data)
    if ps is None:
        return [], 0, 0
    trunks, leaves = freelist_pages(data, ps)
    events = []
    for pg in sorted(leaves):
        for rowid, cell, values in leaf_cells_from_freelist(data, pg, ps):
            item = interpret_row(path, "RECOVERED_FREELIST_CELL", "freelist_leaf", pg, rowid, values, targets)
            if item:
                item["location"] += f", cell={cell}"
                events.append(item)
    return events, len(trunks), len(leaves)


def carve_residual_cells(path, targets, per_page_cap=8):
    """비워진 페이지의 셀 포인터가 0으로 지워졌어도 남아 있는 완전한 옛 테이블 셀을 찾는다.

    완전히 해석된 레코드가 관측된 Codex 테이블 구조와 정확한 스레드 UUID에
    모두 맞을 때만 결과로 낸다. 프리블록의 텍스트 조각만으로는 절대 검증된 레코드로 올리지 않는다.
    """
    b = path.read_bytes()
    ps = page_size(b)
    if ps is None:
        return []
    trunks, leaves = freelist_pages(b, ps)
    target_bytes = [tid.encode('ascii') for tid in targets]
    hits = []
    # 비용이 큰 카빙은 대상 UUID가 실제로 들어 있는 페이지로만 제한한다.
    candidate_pages = set()
    for needle in target_bytes:
        at = 0
        while True:
            at = b.find(needle, at)
            if at < 0:
                break
            candidate_pages.add(at//ps + 1)
            at += len(needle)
    usable = ps - b[20]
    max_local = usable - 35
    min_local = ((usable-12)*32//255)-23
    for pg in sorted(candidate_pages):
        page = b[(pg-1)*ps:pg*ps]
        parent_region = ('FREELIST_LEAF' if pg in leaves else
                         'FREELIST_TRUNK' if pg in trunks else None)
        matched = 0
        for off in range(8, usable-8):
            try:
                size, n1 = uvar(page, off)
                if not (40 <= size <= 8*1024*1024):
                    continue
                rowid, n2 = uvar(page, off+n1)
                if rowid > 10**10:
                    continue
                begin = off+n1+n2
                local = size
                if size > max_local:
                    local = min_local+(size-min_local)%(usable-4)
                    if local > max_local:
                        local = min_local
                if local < 0 or begin+local > usable:
                    continue
                payload = page[begin:begin+local]
                # 이 로컬 셀 페이로드에 대상 UUID가 없으면, UUID가 있는 페이지를 훑어 재구성한 잔여 셀은
                # 관련 없을 가능성이 매우 크다. 수많은 오탐 후보 위치에서 임의의 오버플로 포인터를
                # 따라가지 않는다. UUID가 떨어진 오버플로 페이지에만 있는 경우는 알려진 한계로 남긴다.
                if not any(needle in payload for needle in target_bytes):
                    continue
                if size > local:
                    if begin+local+4 > usable:
                        continue
                    ov = int.from_bytes(page[begin+local:begin+local+4], 'big')
                    visited = set()
                    while len(payload) < size:
                        if not (0 < ov <= len(b)//ps) or ov in visited:
                            raise ValueError('broken overflow')
                        visited.add(ov)
                        ovpg = b[(ov-1)*ps:ov*ps]
                        ov = int.from_bytes(ovpg[:4],'big')
                        payload += ovpg[4:4+min(usable-4,size-len(payload))]
                if len(payload)!=size:
                    continue
                region = parent_region or classify_btree_region(page, pg, off, ps)
                if region not in ('FREELIST_LEAF', 'FREEBLOCK_PAYLOAD',
                                  'UNALLOCATED_INSIDE_BTREE_PAGE'):
                    continue
                v = record_values(payload)
                e = interpret_row(path, 'RECOVERED_RESIDUAL_CELL', region,
                                  pg, rowid, v, targets)
                if e:
                    e['location'] += f', reconstructed_cell_offset={off}'
                    hits.append(e)
                    matched += 1
                    if per_page_cap and matched >= per_page_cap:
                        break
            except (ValueError,UnicodeDecodeError,IndexError,struct.error):
                continue
    return hits


# 프리리스트 페이지 등에서 대상 UUID 문자열이 나타나는 위치를 찾는다 (진단용)
def raw_uuid_hits(path, targets, limit):
    b = path.read_bytes()
    ps = page_size(b)
    if ps is None:
        return {}
    trunks, leaves = freelist_pages(b, ps)
    result = {}
    for tid in targets:
        needle = tid.encode("ascii")
        positions = []
        start = 0
        while True:
            at = b.find(needle, start)
            if at < 0:
                break
            pg = at//ps + 1
            region = "FREELIST_TRUNK" if pg in trunks else "FREELIST_LEAF" if pg in leaves else "ALLOCATED_OR_OLD_PAGE"
            if len(positions) < limit:
                positions.append(f"page={pg}, offset={at} (0x{at:X}), region={region}")
            start = at + len(needle)
        if positions:
            result[tid] = positions
    return result


# WAL 파일에서 대상 UUID가 들어 있는 프레임 위치를 찾는다 (진단용)
def wal_hits(path, targets, limit):
    b = path.read_bytes()
    if len(b) < 32 or int.from_bytes(b[:4], "big") not in (0x377f0682, 0x377f0683):
        return {}
    ps = int.from_bytes(b[8:12], "big")
    ps = 65536 if ps == 1 else ps
    if not (512 <= ps <= 65536 and ps & (ps-1) == 0):
        return {}
    salt = b[16:24]
    stride = 24+ps
    result = defaultdict(list)
    for idx in range((len(b)-32)//stride):
        at = 32 + idx*stride
        h = b[at:at+24]
        if h[8:16] != salt:
            continue  # 솔트가 맞는 검증 가능한 프레임 후보가 아님
        pgno = int.from_bytes(h[:4], "big")
        if pgno == 0:
            continue
        page = b[at+24:at+24+ps]
        for tid in targets:
            start = 0
            while True:
                pos = page.find(tid.encode("ascii"), start)
                if pos < 0:
                    break
                if len(result[tid]) < limit:
                    result[tid].append(f"frame={idx+1}, page={pgno}, WAL_offset={at+24+pos}, checksum=UNVERIFIED")
                start = pos + 36
    return result


# 숫자 시각(초/밀리초/마이크로초/나노초)을 사람이 읽을 수 있는 문자열로
def fmt_time(v):
    try:
        if not isinstance(v, (float,int)):
            return str(v) if v is not None else "unknown"
        x = float(v)
        if x > 1e17:
            x /= 1e9
        elif x > 1e14:
            x /= 1e6
        elif x > 1e11:
            x /= 1e3
        if 946684800 < x < 4102444800:
            return datetime.fromtimestamp(x,timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return str(v)
    except (ValueError,OverflowError,OSError):
        return str(v)


# 복원 이벤트 하나를 콘솔에 출력 (종류별 요약 또는 전체 JSON)
def show_event(event, max_chars, full_json=False):
    print(f"  [복원] {event['kind']} | {event['method']} | {event['source']}")
    print(f"         위치={event.get('location')} | 시간={fmt_time(event.get('timestamp'))}")
    if 'turn_id' in event:
        print(f"         turn={event.get('turn_id')} | item={event.get('item_id')}")
    p = event.get("payload")
    if full_json:
        msg = json.dumps(p,ensure_ascii=False,indent=2,default=str)
    elif isinstance(p,dict):
        if event['kind'] in ('userMessage','agentMessage'):
            msg = str(p.get('text') or p.get('content') or p)
        elif event['kind'] == 'commandExecution':
            msg = f"command={p.get('command')} | status={p.get('status')} | output={p.get('aggregatedOutput')}"
        elif event['kind'] == 'runtime_log':
            msg = f"{p.get('level')} {p.get('target')}: {p.get('feedback_log_body')}"
        elif event['kind'] == 'thread_metadata':
            msg = (f"title={p.get('title')!r}\n"
                   f"first_user_message={p.get('first_user_message')!r}\n"
                   f"rollout_path={p.get('rollout_path')}\n"
                   f"cwd={p.get('cwd')}")
        else:
            msg = json.dumps(p,ensure_ascii=False,default=str)
    else:
        msg = str(p)
    if len(msg) > max_chars and not full_json:
        msg = msg[:max_chars]+f"... [출력 축약; --max-chars로 조정]"
    for line in msg.splitlines() or ['']:
        print('         '+line)




# ----- 대상 탐색, 바이트 영역 분류, 검증된 WAL 프레임 -----

# Global 상태 파일에서 삭제 표시 스레드 ID와 프로젝트 없는 스레드 ID 목록을 모은다
def load_global_catalog(root, quiet=False):
    markers, projectless = set(), set()
    for name in ('.codex-global-state.json', '.codex-global-state.json.bak'):
        p = root / name
        if not p.is_file():
            if not quiet: print('[GLOBAL 미발견]', p)
            continue
        try:
            raw = p.read_bytes()
            obj = json.loads(raw.decode('utf-8-sig'))
            global_ids(obj, markers)
            # 중첩 JSON을 따라가며 projectless-thread-ids 값을 모은다
            def walk(x):
                if isinstance(x, dict):
                    for k,v in x.items():
                        if k == 'projectless-thread-ids' and isinstance(v,list):
                            projectless.update(s.lower() for s in v if isinstance(s,str) and UUID.fullmatch(s))
                        walk(v)
                elif isinstance(x,list):
                    for v in x: walk(v)
                elif isinstance(x,str) and x.lstrip().startswith(('{','[')):
                    try: walk(json.loads(x))
                    except (ValueError,RecursionError): pass
            walk(obj)
            if not quiet: print(f'[GLOBAL] {name}, SHA256={hashlib.sha256(raw).hexdigest()}, marker_total={len(markers)}, projectless_total={len(projectless)}')
        except (OSError,ValueError,RecursionError) as exc:
            print(f'[WARN] Global State cannot be parsed: {p}: {exc}',file=sys.stderr)
    return markers,projectless



def load_global_prompt_history(root, quiet=False):
    """스레드별 prompt-history(입력창 기록)를 읽고, 스냅샷과 정확한 출처를 각각 보존한다.

    이 배열은 입력창 입력 이력이지, 독립적으로 검증된 턴 단위 userMessage 이벤트가 아니다.
    항목마다 믿을 수 있는 개별 시각이 없다.
    """
    catalog = defaultdict(dict)
    for filename in ('.codex-global-state.json', '.codex-global-state.json.bak'):
        path = root / filename
        if not path.is_file():
            continue
        try:
            blob = path.read_bytes()
            obj = json.loads(blob.decode('utf-8-sig'))
            digest = hashlib.sha256(blob).hexdigest()
        except (OSError, ValueError) as exc:
            print(f'[WARN] prompt-history source unreadable: {path}: {exc}', file=sys.stderr)
            continue

        # 중첩 JSON을 따라가며 prompt-history 항목을 (위치, 문장, 출처)로 모은다
        def walk(value, location='root', depth=0):
            if depth > 32:
                return
            if isinstance(value, dict):
                for key, child in value.items():
                    next_loc = location + '.' + str(key)
                    if key == 'prompt-history' and isinstance(child, dict):
                        for raw_tid, entries in child.items():
                            if not isinstance(raw_tid, str) or not UUID.fullmatch(raw_tid):
                                continue
                            if not isinstance(entries, list):
                                continue
                            tid = raw_tid.lower()
                            for index, prompt in enumerate(entries):
                                if not isinstance(prompt, str) or not prompt.strip():
                                    # 알 수 없는 형식은 전송된 프롬프트처럼 보이게 하지 않는다.
                                    continue
                                # *다른* 목록 위치에 같은 내용이 있으면 반복 입력일 수 있다:
                                # 위치마다 보존하고, 스냅샷 간에는 같은 위치·같은 문장만 합친다.
                                key2 = (index, prompt)
                                record = catalog[tid].setdefault(key2, {
                                    'index': index,
                                    'text': prompt,
                                    'sources': []
                                })
                                record['sources'].append({
                                    'file': filename,
                                    'sha256': digest,
                                    'json_path': f'{next_loc}[{raw_tid}][{index}]'
                                })
                    walk(child, next_loc, depth+1)
            elif isinstance(value, list):
                for i, child in enumerate(value):
                    walk(child, f'{location}[{i}]', depth+1)
            elif isinstance(value, str) and value.lstrip().startswith(('{', '[')):
                try:
                    decoded = json.loads(value)
                except ValueError:
                    return
                if isinstance(decoded, (dict, list)):
                    walk(decoded, location+'(JSON-string)', depth+1)

        walk(obj)
    return {tid: list(by_key.values()) for tid, by_key in catalog.items()}


# 스레드의 Global 입력 기록을 콘솔에 출력 (시각 없음 주의 문구 포함)
def show_global_prompt_history(tid, prompt_catalog, descriptions=None):
    prompts = prompt_catalog.get(tid, [])
    print(f'[GLOBAL PROMPT-HISTORY] stored_input_entries={len(prompts)} '
          '(not independent SQLite messages; ordering across snapshots not verified)')
    if not prompts:
        print('  Not found in available Global State snapshots.')
        return
    for p in prompts:
        print(f"  [GLOBAL PROMPT {p['index']+1}] {p['text']}")
        for source in p['sources']:
            print(f"       source={source['file']} sha256={source['sha256']} "
                  f"path={source['json_path']}")
    print('  [CAUTION] prompt-history has no per-prompt timestamp and does not '
          'prove a complete dialogue or AI responses.')

# 페이지 안의 바이트 위치가 B-트리의 어느 영역(셀, 프리블록, 미할당, 헤더)인지 분류
def classify_btree_region(page, page_no, off, ps):
    base = 100 if page_no == 1 else 0
    if len(page)<base+8 or page[base] not in (2,5,10,13):
        return 'UNKNOWN_PAGE_STRUCTURE'
    hsize=8 if page[base] in (10,13) else 12
    n=int.from_bytes(page[base+3:base+5],'big')
    pointer_end=base+hsize+2*n
    start=int.from_bytes(page[base+5:base+7],'big')
    if start==0 and ps==65536: start=65536
    if pointer_end>ps or start>ps: return 'INVALID_BTREE_HEADER'
    f=int.from_bytes(page[base+1:base+3],'big')
    seen=set()
    while f and f not in seen:
        seen.add(f)
        if f+4>ps: break
        nxt=int.from_bytes(page[f:f+2],'big')
        size=int.from_bytes(page[f+2:f+4],'big')
        if size<4 or f+size>ps: break
        if f+4<=off<f+size: return 'FREEBLOCK_PAYLOAD'
        if f<=off<f+4: return 'FREEBLOCK_HEADER'
        f=nxt
    if pointer_end<=off<start: return 'UNALLOCATED_INSIDE_BTREE_PAGE'
    if base<=off<pointer_end: return 'PAGE_HEADER_OR_POINTERS'
    return 'BTREE_CELL_OR_OTHER'


# DB 파일 전체에서 UUID 문자열을 모두 찾는다 (약한 후보)
def discover_raw_uuids(path):
    # 원시 문자열 일치는 약하고 검증되지 않은 후보다. 호출하는 쪽은 카탈로그 ID를 우선한다.
    blob=path.read_bytes()
    found=set()
    for value in re.finditer(rb'(?<![0-9a-fA-F])[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}(?![0-9a-fA-F])',blob):
        found.add(value.group().decode('ascii').lower())
    return found


# 구조가 확인된 SQLite 레코드(살아 있는 테이블 + 프리리스트 셀)에서 스레드 ID를 찾는다
def discover_structured(root, dbs):
    # 형식이 맞고 파싱에 성공한 SQLite 레코드와 살아 있는 스레드 테이블만 사용한다.
    result=set()
    for p in dbs:
        if v5_db_family(p) in ('state','history','logs'):
            try:
                with main_db_conn(p) as conn:
                    table,col=('threads','id') if v5_db_family(p)=='state' else ('thread_items','thread_id')
                    for (value,) in conn.execute(f'SELECT {col} FROM {table}'):
                        if isinstance(value,str) and UUID.fullmatch(value):
                            result.add(value.lower())
            except sqlite3.Error: pass
        # 알려진 Codex 테이블 형식만 사용하고, 알 수 없는 스키마는 원시 단서로 따로 처리한다.
        if v5_db_family(p) not in ('state','history','logs','catalog'):
            continue
        data=p.read_bytes();ps=page_size(data)
        if ps is None: continue
        _,leaves=freelist_pages(data,ps)
        for pg in leaves:
            for rowid,cell,v in leaf_cells_from_freelist(data,pg,ps):
                if v5_db_family(p)=='history' and len(v)==8 and isinstance(v[0],str) and UUID.fullmatch(v[0]):
                    try:
                        obj=json.loads(v[5]) if isinstance(v[5],str) else None
                        if isinstance(obj,dict) and obj.get('type')==v[6]:
                            result.add(v[0].lower())
                    except (ValueError,TypeError): pass
                elif v5_db_family(p)=='state' and len(v)>=18 and isinstance(v[0],str) and UUID.fullmatch(v[0]):
                    result.add(v[0].lower())
                elif v5_db_family(p)=='logs' and len(v)==12 and isinstance(v[9],str) and UUID.fullmatch(v[9]):
                    result.add(v[9].lower())
                elif v5_db_family(p)=='catalog' and len(v)==17 and isinstance(v[1],str) and UUID.fullmatch(v[1]):
                    result.add(v[1].lower())
    return result


# SQLite WAL 체크섬 계산 (누적 방식)
def wal_checksum(buf, initial, endian):
    s1,s2=initial
    if len(buf)%8: raise ValueError('WAL checksum input not divisible by 8')
    for i in range(0,len(buf),8):
        x=int.from_bytes(buf[i:i+4],endian)
        y=int.from_bytes(buf[i+4:i+8],endian)
        s1=(s1+x+s2)&0xffffffff
        s2=(s2+y+s1)&0xffffffff
    return (s1,s2)


def iter_valid_wal_frames(path):
    """WAL 헤더와 프레임 누적 체크섬을 검증하며, 유효하지 않은 경계에서 멈춘다.

    체크섬이 맞는 프레임이라도 커밋된 트랜잭션의 일부라는 보장은 없다.
    """
    raw=path.read_bytes()
    if len(raw)<32: return
    magic=int.from_bytes(raw[:4],'big')
    if magic not in (0x377f0682,0x377f0683): return
    ps=int.from_bytes(raw[8:12],'big') or 65536
    if ps!=65536 and not (512<=ps<=65536 and ps&(ps-1)==0): return
    expected=(int.from_bytes(raw[24:28],'big'),int.from_bytes(raw[28:32],'big'))
    # 입력 워드의 바이트 순서는 실제로 헤더 체크섬과 맞는 계산 방식으로 정한다(플랫폼을 가정하지 않음).
    modes=[mode for mode in ('big','little') if wal_checksum(raw[:24],(0,0),mode)==expected]
    if len(modes)!=1:
        print(f'[WAL] invalid/ambiguous header checksum: {path}')
        return
    mode=modes[0];s=expected;salt=raw[16:24]
    for index in range((len(raw)-32)//(24+ps)):
        off=32+index*(24+ps)
        hdr=raw[off:off+24]
        payload=raw[off+24:off+24+ps]
        if hdr[8:16]!=salt: break
        pg=int.from_bytes(hdr[:4],'big')
        if pg==0: break
        cs=wal_checksum(hdr[:8]+payload,s,mode)
        expected_frame=(int.from_bytes(hdr[16:20],'big'),int.from_bytes(hdr[20:24],'big'))
        if cs!=expected_frame:
            print(f'[WAL] checksum chain ends before frame {index+1}: {path}')
            break
        s=cs
        yield {'frame':index+1,'db_page':pg,'frame_offset':off,
               'page_offset':off+24,'page_size':ps,'committed_here':int.from_bytes(hdr[4:8],'big')!=0,
               'page':payload}


def wal_page_cells(page, ps, *, db_page=2, lookup=None, reserved=0):
    """체크섬 검증된 프레임에서 완전한 리프 레코드를 해석한다 (오버플로 포함).

    오버플로 페이지는 먼저 프레임 시점의 WAL 스냅샷에서, 다음으로 수집한 변경 불가 메인 DB에서 찾는다.
    검증된 완전한 체인이 없으면 레코드를 돌려주지 않는다. 1번 페이지의 B-트리는 100바이트 뒤에서 시작한다.
    """
    base = 100 if db_page == 1 else 0
    if len(page) != ps or len(page) < base + 8 or page[base] != 13:
        return
    usable = ps - reserved
    n = int.from_bytes(page[base+3:base+5], 'big')
    if n > min((usable-base-8)//2, 4096):
        return
    for j in range(n):
        off = int.from_bytes(page[base+8+2*j:base+10+2*j], 'big')
        if not (base+8 <= off < usable):
            continue
        try:
            rowid, values, overflow = wal_decode_cell(page, off, usable, lookup)
            yield rowid, j, values, overflow
        except (ValueError, UnicodeDecodeError, IndexError, struct.error):
            pass


# 셀 하나를 해석해 (rowid, 레코드 값)을 돌려준다 (오버플로 페이지는 lookup으로 따라감)
def wal_decode_cell(page, off, usable, lookup=None):
    size, n1 = uvar(page, off)
    rowid, n2 = uvar(page, off+n1)
    begin = off+n1+n2
    if not (0 < size <= 16*1024*1024):
        raise ValueError('implausible payload')
    max_local = usable - 35
    min_local = ((usable-12)*32//255)-23
    local = size
    if size > max_local:
        local = min_local + (size-min_local) % (usable-4)
        if local > max_local:
            local = min_local
    if begin+local > usable:
        raise ValueError('local payload exceeds page')
    payload = bytearray(page[begin:begin+local])
    uses_overflow = size > local
    if uses_overflow:
        if lookup is None or begin+local+4 > usable:
            raise ValueError('overflow lookup unavailable')
        pgno = int.from_bytes(page[begin+local:begin+local+4], 'big')
        visited = set()
        while len(payload) < size:
            if not pgno or pgno in visited or len(visited)>8192:
                raise ValueError('broken overflow chain')
            visited.add(pgno)
            ovpage = lookup(pgno)
            if ovpage is None or len(ovpage) < usable:
                raise ValueError('unavailable overflow page at this WAL frame')
            pgno = int.from_bytes(ovpage[:4], 'big')
            payload.extend(ovpage[4:4+min(usable-4, size-len(payload))])
        if len(payload) != size:
            raise ValueError('incomplete overflow')
    return rowid, record_values(bytes(payload)), uses_overflow


def wal_residual_cells(page, ps, db_page, targets, lookup, reserved=0, per_page_cap=25):
    """명확히 구분된 WAL B-트리 빈 영역 안에서만 완전한 레코드를 카빙한다.

    대화가 삭제됐는지에 대해서는 아무것도 말하지 않는다. WAL 스냅샷은 이전의 유효한 버전이거나
    커밋되지 않은 작업일 수 있다.
    """
    if not targets or len(page)!=ps:
        return
    base = 100 if db_page == 1 else 0
    if page[base] != 13:
        return
    usable = ps-reserved
    regions=set()
    for tid in targets:
        needle=tid.encode('ascii')
        offset=0
        while (pos:=page.find(needle,offset))>=0:
            offset=pos+len(needle)
            if pos>=usable:
                continue
            region=region_bounds(page,db_page,pos,ps)
            if region and region[0] in ('UNALLOCATED','FREEBLOCK_PAYLOAD'):
                regions.add(region)
    observed=set()
    matched=0
    for label,start,end in sorted(regions):
        # 프리블록 헤더는 페이로드가 아니다. 후보 셀은 (참조한 오버플로 페이지를 제외하고)
        # 이 빈 영역 안에 완전히 들어 있어야 한다.
        for off in range(max(base+8,start),min(usable-8,end-4)):
            if off in observed:
                continue
            try:
                size,n1=uvar(page,off)
                _,n2=uvar(page,off+n1)
                begin=off+n1+n2
                local=size
                max_local=usable-35
                if size>max_local:
                    min_local=((usable-12)*32//255)-23
                    local=min_local+(size-min_local)%(usable-4)
                    if local>max_local:
                        local=min_local
                # 포렌식 절제: 로컬 레코드와 포인터가 식별된 빈 영역에 들어맞고, 정확한 대상 UUID를 포함해야 한다.
                cell_end=begin+local+(4 if size>local else 0)
                if not (40<=size<=8*1024*1024 and begin>=start and cell_end<=end):
                    continue
                if not any(tid.encode('ascii') in page[begin:begin+local] for tid in targets):
                    continue
                rowid,values,overflow=wal_decode_cell(page,off,usable,lookup)
                observed.add(off)
                yield rowid,off,values,label,overflow
                matched+=1
                if per_page_cap and matched>=per_page_cap:
                    return
            except (ValueError,UnicodeDecodeError,IndexError,struct.error):
                pass


def wal_snapshot_lookups(frames, main_db_bytes, page_bytes):
    """각 트랜잭션 스냅샷에서 마지막으로 관측된 프레임을 기준으로 페이지를 찾는다.

    WAL은 한 트랜잭션에서 리프 페이지를 오버플로 페이지보다 먼저 쓸 수 있으므로,
    리프보다 앞서 쓴 페이지만 쓰면 유효한 메시지를 놓친다. 뒤에 커밋 표시가 있는 프레임은
    그 트랜잭션의 커밋 경계를 쓴다. 이는 재구성 후보일 뿐, 옛 프레임 버전이 커밋됐다는 증거가 아니다
    (중간 버전이 따로 있을 수도 있다).
    """
    pages=defaultdict(list)
    for frame in frames:
        pages[frame['db_page']].append((frame['frame'],frame['page']))
    next_commits={}
    following=None
    for f in reversed(frames):
        if f['committed_here']:
            following=f['frame']
        next_commits[f['frame']]=following or f['frame']
    indexes={pg:[i for i,_ in rows] for pg,rows in pages.items()}
    # 프레임 번호 시점의 페이지 조회 함수를 만든다
    def for_frame(frame_number):
        at_frame=next_commits[frame_number]
        # 페이지 번호의 해당 시점 내용 (WAL에 없으면 메인 DB)
        def lookup(pgno):
            if not isinstance(pgno,int) or pgno<1:
                return None
            versions=pages.get(pgno)
            if versions:
                j=bisect_right(indexes[pgno],at_frame)-1
                if j>=0:
                    return versions[j][1]
            start=(pgno-1)*page_bytes
            return (main_db_bytes[start:start+page_bytes]
                    if start+page_bytes<=len(main_db_bytes) else None)
        return lookup
    return for_frame


def wal_events(path,targets,max_hints=3,carve_cap=25,scan_stats=None):
    """검증된 WAL 프레임 이력과 프레임 시점 오버플로 스냅샷을 사용한다.

    현재 SHM은 필요 없다: SHM은 휘발성 색인일 뿐 메시지 저장소가 아니다.
    결과 레코드마다 마지막으로 확인된 커밋 경계 안인지 남기며,
    커밋된 프레임이라도 스레드 삭제의 증거는 아니다.
    """
    events=[]
    leads=defaultdict(list)
    frames=list(iter_valid_wal_frames(path))
    if scan_stats is not None:
        scan_stats['wal_valid_frames']=len(frames)
        scan_stats['wal_committed_boundary']=max((f['frame'] for f in frames if f['committed_here']),default=0)
        scan_stats['wal_overflow_records']=0
        scan_stats['wal_residual_records']=0
    if not frames:
        return events,leads
    ps=frames[0]['page_size']
    primary=Path(str(path)[:-4])
    try:
        db_bytes=primary.read_bytes()
        reserved=db_bytes[20] if page_size(db_bytes[:100]) == ps else 0
    except (OSError,IndexError):
        db_bytes=b''
        reserved=0
    # 트랜잭션은 오버플로 체인보다 리프를 먼저 쓸 수 있다.
    # 수집한 트랜잭션 끝 시점 스냅샷으로 완전한 레코드 바이트를 찾는다.
    snapshots=wal_snapshot_lookups(frames,db_bytes,ps)
    last_commit=max((f['frame'] for f in frames if f['committed_here']),default=0)
    for frame in frames:
        page=frame['page']
        lookup=snapshots(frame['frame'])
        for tid in (targets or ()):
            at=page.find(tid.encode('ascii'))
            if at>=0 and len(leads[tid])<max_hints:
                leads[tid].append(
                    f"frame={frame['frame']}, db_page={frame['db_page']}, "
                    f"WAL_file_offset={frame['page_offset']+at} "
                    f"(0x{frame['page_offset']+at:X}); checksum=VALID; "
                    f"within_observed_commit_boundary={frame['frame']<=last_commit}")
        records=[]
        for rowid,cell,values,overflow in wal_page_cells(
                page,ps,db_page=frame['db_page'],lookup=lookup,reserved=reserved):
            records.append((rowid,cell,values,overflow,'WAL_LEAF_CELL','WAL_VALID_FRAME_SNAPSHOT'))
        for rowid,cell,values,region,overflow in wal_residual_cells(
                page,ps,frame['db_page'],targets,lookup,reserved,carve_cap):
            records.append((rowid,cell,values,overflow,region,'WAL_RESIDUAL_CELL'))
        for rowid,cell,values,overflow,region,method in records:
            event=interpret_row(primary,method,region,frame['db_page'],rowid,values,targets)
            if not event:
                continue
            event['location']+=(f", frame={frame['frame']}, WAL_offset={frame['page_offset']}, "
                                f"cell_or_offset={cell}")
            event['wal_commit_marker_on_this_frame']=frame['committed_here']
            event['wal_within_observed_commit_boundary']=frame['frame']<=last_commit
            event['wal_overflow_pages_used']=overflow
            event['wal_frame']=frame['frame']
            event['wal_db_page']=frame['db_page']
            event['wal_note']='Frame checksum valid; no standalone proof of conversation deletion.'
            events.append(event)
            if scan_stats is not None:
                if overflow:
                    scan_stats['wal_overflow_records']+=1
                if method=='WAL_RESIDUAL_CELL':
                    scan_stats['wal_residual_records']+=1
    return events,leads


def discover_wal_structured_threads(dbs):
    """알려진 표시만이 아니라, 스키마 검증을 강하게 통과한 새 ID를 WAL에서 찾는다.

    state/history/logs 계열만 새 스레드를 추가할 수 있다.
    카탈로그에는 계정 전체의 ID가 많아 뒷받침 용도로만 쓴다.
    """
    found=set()
    for db in dbs:
        if v5_db_family(db) not in ('state','history','logs'):
            continue
        wal=Path(str(db)+'-wal')
        if not wal.is_file():
            continue
        try:
            frames=list(iter_valid_wal_frames(wal))
            if not frames:
                continue
            primary=db.read_bytes()
            reserved=primary[20] if page_size(primary[:100])==frames[0]['page_size'] else 0
            ps=frames[0]['page_size']
            snapshots=wal_snapshot_lookups(frames,primary,ps)
            for frame in frames:
                lookup=snapshots(frame['frame'])
                for rowid,_,values,_ in wal_page_cells(
                        frame['page'],ps,db_page=frame['db_page'],lookup=lookup,reserved=reserved):
                    record=interpret_row(db,'WAL_TYPED_DISCOVERY','WAL_PAGE',
                                         frame['db_page'],rowid,values,None)
                    if record:
                        found.add(record['thread_id'])
        except (OSError,MemoryError,ValueError,IndexError,struct.error):
            continue
    return found


def inspect_database_sidecars(db):
    """WAL 내용 검증 + 휘발성 SHM 헤더/색인 검증.

    증거 메타데이터일 뿐 대화 내용의 출처나 삭제 증거가 아니다.
    전체 WAL 페이지 해석은 wal_events()가 따로 한다.
    """
    wal=Path(str(db)+'-wal')
    shm=Path(str(db)+'-shm')
    out={'db':db.name,'wal_exists':wal.is_file()}
    frames=[]
    if wal.is_file():
        try:
            # 보조 감사 기록에 모든 페이지 이미지를 보관하지 않는다.
            frames=[{'frame':f['frame'],'db_page':f['db_page'],
                     'committed_here':f['committed_here']}
                    for f in iter_valid_wal_frames(wal)]
            out['wal_checksum_valid_frames']=len(frames)
            out['wal_observed_commit_boundary']=max(
                (f['frame'] for f in frames if f['committed_here']),default=0)
            with wal.open('rb') as handle:
                wal_header=handle.read(12)
            page_bytes=int.from_bytes(wal_header[8:12],'big') or 65536
            out['wal_extra_bytes_unverified']=max(0,wal.stat().st_size-32-len(frames)*(page_bytes+24))
        except (OSError,MemoryError,ValueError) as exc:
            out['wal_audit_error']=str(exc)
    try:
        out.update(inspect_shm(shm,wal if wal.is_file() else None,frames if wal.is_file() else None))
    except (OSError,MemoryError,ValueError) as exc:
        out.update(shm_status='SHM_INSPECTION_ERROR',shm_error=str(exc))
    return out


def region_bounds(page,page_no,off,ps):
    """UUID가 들어 있는 정확한 B-트리 프리블록/미할당 바이트 범위를 잘라낸다."""
    base=100 if page_no==1 else 0
    if len(page)<base+8 or page[base] not in (2,5,10,13):return None
    n=int.from_bytes(page[base+3:base+5],'big')
    pointer_end=base+(8 if page[base] in (10,13) else 12)+n*2
    start=int.from_bytes(page[base+5:base+7],'big')
    if start==0 and ps==65536:start=ps
    if pointer_end<=off<start<=ps:return ('UNALLOCATED',pointer_end,start)
    block=int.from_bytes(page[base+1:base+3],'big');seen=set()
    while block and block not in seen:
        seen.add(block)
        if block+4>ps:break
        nxt=int.from_bytes(page[block:block+2],'big')
        length=int.from_bytes(page[block+2:block+4],'big')
        if length<4 or block+length>ps:break
        if block+4<=off<block+length:return ('FREEBLOCK',block+4,block+length)
        block=nxt
    return None


def fragment_leads(path,targets,max_fragments,max_chars):
    """영역 안의 문자열만 뽑는다. 레코드/메시지로 귀속하지 않는다."""
    data=path.read_bytes();ps=page_size(data)
    if ps is None:return {}
    _,leaves=freelist_pages(data,ps)
    result=defaultdict(list)
    for tid in targets:
        needle=tid.encode('ascii');start=0
        while len(result[tid])<max_fragments:
            pos=data.find(needle,start)
            if pos<0:break
            start=pos+len(needle)
            pg=pos//ps+1;page=data[(pg-1)*ps:pg*ps];off=pos%ps
            if pg in leaves:
                area=('FREELIST_PAGE',0,len(page))
            else:
                area=region_bounds(page,pg,off,ps)
                if area is None:continue
            label,a,b=area
            # 원시 문맥을 출력할 때 페이지/영역 경계를 넘지 않는다.
            before=max(a,off-120);after=min(b,off+len(needle)+max_chars)
            raw=page[before:after]
            decoded=''.join(c if c.isprintable() and c not in '\r\n\t' else ' '
                            for c in raw.decode('utf-8','replace'))
            if len(decoded)>max_chars:decoded=decoded[:max_chars]+' …'
            result[tid].append(f'{path.name} page={pg} file_offset={pos} '
                               f'region={label} UNVERIFIED_FRAGMENT: {decoded}')
    return result


# 프리리스트 페이지에서 대상 UUID 위치를 빠르게 찾는다 (진단용)
def raw_hits_fast(path,targets,limit):
    b=path.read_bytes();ps=page_size(b)
    if ps is None:return {}
    trunks,leaves=freelist_pages(b,ps)
    result={}
    for tid in targets:
        locs=[];at=0;needle=tid.encode('ascii')
        while len(locs)<limit:
            at=b.find(needle,at)
            if at<0:break
            pg=at//ps+1;off=at%ps
            region='FREELIST_TRUNK' if pg in trunks else ('FREELIST_LEAF' if pg in leaves else classify_btree_region(b[(pg-1)*ps:pg*ps],pg,off,ps))
            locs.append(f'{path.name}: page={pg}, byte_offset={at}, region={region}')
            at+=len(needle)
        if locs:result[tid]=locs
    return result


# 물리적 출처 식별자 (파일, 페이지/rowid 또는 방식/위치, 내용)
def physical_identity(e):
    loc=e.get('location','')
    if e.get('method') in ('RECOVERED_FREELIST_CELL','RECOVERED_RESIDUAL_CELL'):
        m=re.search(r'page=(\d+), rowid=(\d+)',loc)
        if m:
            return (e.get('source'),m.group(1),m.group(2),event_identity(e))
    return (e.get('source'),e.get('method'),loc,event_identity(e))

# 내용 기준 식별자 (스레드, 종류, 항목 ID, 시각, 페이로드)
def event_identity(e):
    # 원래 물리적 출처는 각각 보존하면서, 완전히 같은 내용만 중복으로 합친다.
    return (e['thread_id'],e['kind'],e.get('item_id'),e.get('timestamp'),
            json.dumps(e.get('payload'),ensure_ascii=False,default=str,sort_keys=True))


# 콘솔 인코딩 오류 없이 출력
def safe_print(s):
    # 손상된 과거 UTF-8 때문에 Windows 콘솔 출력이 실패하지 않도록 한다.
    try: print(s)
    except UnicodeEncodeError:
        print(str(s).encode(sys.stdout.encoding or 'utf-8','backslashreplace').decode(sys.stdout.encoding or 'utf-8'))



# ============================================================================
# ACTF: 독립 포렌식 복원 및 읽기 쉬운 한글 보고서
# ============================================================================
import os
import itertools
from datetime import timedelta

V4_FORMAT = "actf-codex-recovery-v4"
KST = timezone(timedelta(hours=9))
V4_LIMITATIONS = [
    "A deleted JSONL cannot be reconstructed from a historical path string.",
    "Global prompt-history records composer history, not verified sent message events; no per-input timestamps.",
    "SQLite free-list/residual matches may reflect historical records or page reuse; absence of hits is not proof of absence.",
    "WAL checksum-valid frames can be uncommitted and are not proof of deletion.",
    "Runtime log observations and unverified binary fragments are not complete conversation messages.",
    "When event order cannot be corroborated, retain source-local order without assigning an invented date.",
    "This version does not carve file-system free space, disk images, recovered deleted JSONLs, or inaccessible remote data."
]


def enable_unicode_output():
    """가능한 범위에서 콘솔 출력만 UTF-8로 설정한다 (사람용 파일은 UTF-8 BOM 사용)."""
    if os.name == 'nt':
        try:
            import ctypes
            if sys.stdout.isatty():
                ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except (OSError, AttributeError):
            pass
    for dest in (sys.stdout, sys.stderr):
        try:
            dest.reconfigure(encoding='utf-8', errors='backslashreplace')
        except (AttributeError, ValueError, OSError):
            pass


# 파일 SHA-256 해시 (1MB 단위로 읽음)
def sha_file(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(data)
    return h.hexdigest()


# 증거 근거(파일 상대경로, 방식, 해시, 위치, 영역)를 만든다
def source_ref(path, root, digest=None, location=None, method=None, region=None, extra=None):
    try:
        relative = str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        relative = str(path)
    ref = {'file': relative, 'method': method or 'OBSERVED',
           'sha256': digest or (sha_file(path) if path.is_file() else None),
           'location': location, 'region': region}
    if extra:
        ref.update(extra)
    return ref


def time_entry(value, basis='event_record', precision=None):
    """알 수 없거나 해석할 수 없는 시각은 비워 둔다. 스레드 정보로 추정하지 않는다."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().replace('.', '', 1).isdigit()):
            n = float(value)
            if n > 1e17: n /= 1e9; precision = precision or 'nanosecond_source'
            elif n > 1e14: n /= 1e6; precision = precision or 'microsecond_source'
            elif n > 1e11: n /= 1e3; precision = precision or 'millisecond_source'
            elif n > 1e9: precision = precision or 'second_source'
            else: return None
            if not 946684800 <= n <= 4102444800:
                return None
            dt = datetime.fromtimestamp(n, timezone.utc)
        elif isinstance(value, str):
            raw = value.strip()
            if raw.endswith('Z'):
                raw = raw[:-1] + '+00:00'
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                # 시간대 정보가 없으면 로컬이나 UTC로 몰래 가정하지 않는다.
                return None
            dt = dt.astimezone(timezone.utc)
            precision = precision or 'iso_timestamp'
        else:
            return None
        return {'utc': dt.isoformat(timespec='milliseconds'),
                'kst': dt.astimezone(KST).isoformat(timespec='milliseconds'),
                'original_value': value, 'basis': basis,
                'precision': precision or 'unknown', 'estimated': False}
    except (OverflowError, ValueError, OSError, TypeError):
        return None


# 값을 JSON 저장 가능한 형태로 (바이트는 hex)
def safe_jsonable(obj):
    if isinstance(obj, dict):
        return {str(k): safe_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [safe_jsonable(v) for v in obj]
    if isinstance(obj, bytes):
        return {'encoding': 'hex', 'hex': obj.hex()}
    if isinstance(obj, (int, str, float, bool)) or obj is None:
        return obj
    return str(obj)


def text_from_content(content):
    """표시할 텍스트만 뽑고, 원본 JSON 전체는 그대로 둔다."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = []
        for element in content:
            if isinstance(element, str):
                texts.append(element)
            elif isinstance(element, dict):
                if isinstance(element.get('text'), str):
                    texts.append(element['text'])
                elif isinstance(element.get('content'), (str, list)):
                    t = text_from_content(element['content'])
                    if t: texts.append(t)
                elif element.get('type') in ('image', 'input_image', 'image_url'):
                    texts.append('[IMAGE REFERENCE: see raw payload]')
                elif element.get('type') in ('input_audio', 'audio'):
                    texts.append('[AUDIO REFERENCE: see raw payload]')
        return '\n'.join(texts)
    return None


# 항목 종류별 표시 문장 (메시지 본문, 명령+출력, 로그 본문 등)
def display_from_item(item, kind):
    if not isinstance(item, dict):
        return str(item)
    if kind in ('userMessage', 'agentMessage', 'user_message', 'agent_message'):
        return item.get('text') if isinstance(item.get('text'), str) else text_from_content(item.get('content'))
    if kind in ('commandExecution', 'tool_call', 'function_call', 'mcpToolCall'):
        command = item.get('command') or item.get('name') or item.get('server') or ''
        output = item.get('aggregatedOutput') or item.get('output')
        s = str(command) if isinstance(command, str) else json.dumps(command, ensure_ascii=False)
        if isinstance(output, str):
            s += ('\n' + output)
        return s or json.dumps(item, ensure_ascii=False, default=str)
    if kind == 'runtime_log':
        return str(item.get('feedback_log_body') or '')
    if kind == 'desktop_log':
        return str(item.get('line') or '')
    if kind == 'metadata':
        return str(item.get('title') or item.get('first_user_message') or '')
    return item.get('text') if isinstance(item.get('text'), str) else json.dumps(item, ensure_ascii=False, default=str)


# 원본 항목 종류 이름을 복원 표준 종류 이름으로 매핑
def mapped_kind(kind):
    table = {
        'UserMessage': 'user_message', 'userMessage': 'user_message',
        'AgentMessage': 'agent_message', 'agentMessage': 'agent_message',
        'commandExecution': 'command_execution', 'fileChange': 'file_change',
        'mcpToolCall': 'mcp_tool_call', 'webSearch': 'web_search',
        'runtime_log': 'runtime_log', 'thread_metadata': 'thread_metadata',
        'catalog_metadata': 'catalog_metadata', 'reasoning': 'reasoning',
        'prompt_history': 'prompt_history', 'global_draft': 'global_draft',
        'first_input_reference':'first_input_reference',
    }
    return table.get(kind, re.sub(r'(?<!^)(?=[A-Z])', '_', kind).lower())


# 복원 종류별 행위자 (사용자/에이전트/메타데이터 등)
def actor_for_kind(kind):
    if kind == 'user_message': return 'user'
    if kind in ('agent_message', 'reasoning'): return 'agent'
    if kind == 'prompt_history': return 'unknown_composer_history'
    if kind == 'first_input_reference': return 'user_input_reference'
    if kind in ('thread_metadata', 'catalog_metadata'): return 'metadata'
    return 'tool_or_runtime'


# 복원 레코드 색인 -- 중복을 합치면서 물리적 출처별 근거를 모은다
class RecoveryIndex:
    # 루트 폴더와 파일 해시 캐시, 레코드 목록 준비
    def __init__(self, root, source_digests):
        self.root = root
        self.digests = source_digests
        self.records = []
        self._dedup = {}
        self._serial = itertools.count(1)

    # 파일 해시 (한 번 계산한 값은 재사용)
    def digest(self, path):
        key = str(path.resolve())
        if key not in self.digests:
            self.digests[key] = sha_file(path)
        return self.digests[key]

    # 복원 레코드 추가 -- 같은 레코드면 근거만 합치고, 같은 ID의 다른 내용은 따로 보존
    def add(self, tid, kind, payload, evidence, timestamp=None, turn_id=None, item_id=None,
            ordinal=None, source_order=None, verification='structured_record',
            is_message=False, title=None, dedup_key=None, notes=None):
        if not UUID.fullmatch(str(tid)):
            return
        tid = tid.lower()
        canonical_kind = mapped_kind(kind)
        event = {
            'event_id': None, 'session_id': tid, 'thread_id': tid,
            'kind': canonical_kind, 'actor': actor_for_kind(canonical_kind),
            'verification': verification, 'is_complete_message_record': bool(is_message),
            'timestamp': timestamp, 'turn_id': turn_id, 'item_id': item_id,
            'ordinal': ordinal, 'source_order': source_order,
            'display_text': display_from_item(payload, kind), 'raw': safe_jsonable(payload),
            'evidence': [evidence], 'notes': notes or []
        }
        # 강한 식별자가 같거나 완전히 같은 레코드 관측일 때만 중복으로 합친다.
        if dedup_key is None:
            ident = (tid, canonical_kind, item_id, turn_id, ordinal,
                     timestamp['utc'] if timestamp else None,
                     evidence.get('file'),
                     json.dumps(event['raw'], sort_keys=True, ensure_ascii=False, default=str))
        else:
            ident = dedup_key
        if ident in self._dedup:
            existing = self._dedup[ident]
            if existing['raw'] != event['raw'] and dedup_key is not None:
                # WAL 스냅샷에는 같은 원본 항목 ID로 *다른* 과거 버전이 남아 있을 수 있다.
                # 조용히 없애거나 관련 없는 출처와 같은 내용이라고 주장하지 않는다.
                variant_hash = hashlib.sha256(json.dumps(
                    event['raw'], sort_keys=True, ensure_ascii=False,
                    default=str).encode('utf-8')).hexdigest()
                ident = (dedup_key, 'DIFFERING_HISTORICAL_PAYLOAD', variant_hash)
                event['notes'].append(
                    'Different historical payload under the same native item ID; manual review required.')
                existing = self._dedup.get(ident)
                if existing is not None:
                    if evidence not in existing['evidence']:
                        existing['evidence'].append(evidence)
                    return existing
            else:
                if evidence not in existing['evidence']:
                    existing['evidence'].append(evidence)
                if existing.get('timestamp') != timestamp:
                    existing.setdefault('notes', []).append(
                        'Per-source timestamps differ for same native item ID; review underlying evidence.')
                return existing
        fingerprint = json.dumps(ident, ensure_ascii=False, sort_keys=True, default=str)
        event['event_id'] = 'ev_' + hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()[:20]
        self.records.append(event)
        self._dedup[ident] = event
        return event


def load_simple_index(root):
    """알려진 스레드 ID를 보충한다. 임의의 원시 UUID를 스레드로 취급하지 않는다."""
    out = {}
    p = root / 'session_index.jsonl'
    if p.is_file():
        with p.open('r', encoding='utf-8-sig', errors='replace') as handle:
            for line_no, line in enumerate(handle, 1):
                try:
                    item = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if not isinstance(item, dict): continue
                tid = item.get('id') or item.get('thread_id')
                if isinstance(tid, str) and UUID.fullmatch(tid):
                    out[tid.lower()] = {'title': item.get('thread_name') or item.get('title'),
                                        'updated_at': item.get('updated_at'),
                                        'source_index_line': line_no}
    return out


# 루트 아래의 모든 SQLite 파일 목록 (헤더가 올바른 것만)
def db_files(root):
    dbs = []
    for path in root.rglob('*'):
        if path.is_file() and path.name.lower().endswith(EXT):
            try:
                if path.stat().st_size >= 100 and page_size(path.read_bytes()[:100]):
                    dbs.append(path)
            except OSError:
                pass
    return sorted(dbs)


def discover_existing_jsonl(root):
    """파일명이 스레드 UUID 형식으로 끝나는 JSONL만 인정한다."""
    found = {}
    for path in root.rglob('rollout-*.jsonl'):
        match = re.search(r'([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\.jsonl$', path.name)
        if match:
            found.setdefault(match.group(1).lower(), []).append(path)
    return found


# DB 하나에서 살아 있는 행, 프리리스트 셀, 잔여 셀, WAL 레코드를 모두 찾아 복원 색인에 추가
def decode_sqlite_evidence(db, targets, idx, root, include_fragments, max_leads, diagnostic, carve_cap=25, sidecar=None):
    digest = idx.digest(db)
    rel = str(db.relative_to(root))
    live = main_db_live_rows(db, targets)
    pointed, trunks, leaves = main_db_freelist(db, targets)
    residual = carve_residual_cells(db, targets, per_page_cap=carve_cap)
    # 서로 다른 물리적 관측은 모두 보존한다. 같은 행을 포인터와 카빙으로 모두 찾으면
    # 증거 방식이 여러 개인 하나의 레코드로 표현한다.
    physical = set()
    counts = {'live': len(live), 'pointed': len(pointed), 'residual': len(residual),
              'freelist_pages': trunks + leaves, 'wal_records': 0}
    counts['shm_consistency'] = (sidecar or {}).get('shm_status', 'NOT_INSPECTED')
    for event in live + pointed + residual:
        physical_id = physical_identity(event)
        if physical_id in physical:
            continue
        physical.add(physical_id)
        kind = event['kind']
        source = source_ref(db, root, digest, event.get('location'), event.get('method'), event.get('region'))
        # 강한 항목 ID는 같은 항목이 독립적으로 남은 사본들을 하나로 묶는다.
        # 항목 ID 없는 같은 내용의 익명 메시지는 합치지 않는다.
        unique = None
        if kind in ('userMessage', 'agentMessage', 'commandExecution', 'webSearch', 'mcpToolCall') and event.get('item_id'):
            unique = (event['thread_id'], mapped_kind(kind), event.get('item_id'))
        idx.add(event['thread_id'], kind, event.get('payload'), source,
                time_entry(event.get('timestamp'), 'sqlite_record'),
                turn_id=event.get('turn_id'), item_id=event.get('item_id'),
                ordinal=event.get('ordinal'), verification='sqlite_' + str(event['method']).lower(),
                is_message=kind in ('userMessage', 'agentMessage'), dedup_key=unique,
                notes=['SQLite historical record: row/page dates may be stale.'] if event.get('method') != 'ACTIVE_MAIN_DB' else [])
    wp = Path(str(db) + '-wal')
    if wp.is_file():
        idx.digest(wp)
        wal_items, wal_leads = wal_events(wp, targets, max_hints=max_leads,
                                          carve_cap=carve_cap, scan_stats=counts)
        counts['wal_records'] = len(wal_items)
        for event in wal_items:
            kind = event['kind']
            evidence = source_ref(wp, root, idx.digest(wp), event.get('location'), event.get('method'), 'WAL_PAGE',
                                  {'commit_marker_on_frame': event.get('wal_commit_marker_on_this_frame'),
                                   'checksum_valid': True,
                                   'within_observed_commit_boundary': event.get('wal_within_observed_commit_boundary'),
                                   'overflow_pages_used': event.get('wal_overflow_pages_used'),
                                   'shm_consistency': counts.get('shm_consistency')})
            unique = (event['thread_id'], mapped_kind(kind), event.get('item_id')) if event.get('item_id') else None
            idx.add(event['thread_id'], kind, event['payload'], evidence,
                    time_entry(event.get('timestamp'), 'wal_record'),
                    turn_id=event.get('turn_id'), item_id=event.get('item_id'),
                    ordinal=event.get('ordinal'), verification='wal_checksum_valid',
                    is_message=kind in ('userMessage', 'agentMessage'), dedup_key=unique,
                    notes=['WAL checksum valid; transaction boundary annotated; deletion status unproven.'])
        if wal_leads:
            diagnostic.append({'file': str(wp.relative_to(root)), 'type': 'checksum_valid_wal_uuid_leads', 'items': wal_leads})
    if max_leads:
        leads = raw_hits_fast(db, targets, max_leads)
        if leads:
            diagnostic.append({'file': rel, 'type': 'uuid_location_not_message', 'items': leads})
    if include_fragments:
        frags = fragment_leads(db, targets, max_fragments=max_leads or 5, max_chars=320)
        if frags:
            diagnostic.append({'file': rel, 'type': 'unverified_fragment_not_message', 'items': frags})
    return counts


def normalize_jsonl_item(outer):
    """완료된 item을 기본 레코드로 쓰고, response_item은 대체용으로만 쓴다."""
    rtype = outer.get('type')
    payload = outer.get('payload')
    if not isinstance(payload, dict):
        return None
    if rtype == 'event_msg' and payload.get('type') == 'item_completed':
        item = payload.get('item')
        if not isinstance(item, dict): return None
        kind = item.get('type', 'unknown_item')
        timestamp = payload.get('completed_at_ms') or outer.get('timestamp')
        return kind, item, timestamp, payload.get('turn_id'), item.get('id'), outer.get('ordinal'), 'event_completed'
    if rtype == 'event_msg' and payload.get('type') in ('task_started', 'task_complete', 'turn_aborted'):
        return payload['type'], payload, outer.get('timestamp'), payload.get('turn_id'), None, outer.get('ordinal'), 'event_lifecycle'
    if rtype == 'response_item':
        kind = payload.get('type')
        if kind == 'message':
            role = payload.get('role', 'unknown')
            if role not in ('user', 'assistant'): return None
            return ('userMessage' if role == 'user' else 'agentMessage'), payload, outer.get('timestamp'), None, None, outer.get('ordinal'), 'response_item_fallback'
        if kind in ('function_call', 'custom_tool_call', 'function_call_output', 'custom_tool_call_output'):
            return kind, payload, outer.get('timestamp'), None, payload.get('call_id'), outer.get('ordinal'), 'response_tool_item'
    return None


def ingest_existing_jsonl(path, tid, idx, root):
    """현재 존재하는 파일만 읽는다. 삭제된 파일을 되살리거나 필요로 하지 않는다."""
    digest = idx.digest(path)
    primary_fingerprints = set()
    fallback = []
    count = 0
    # 실제 완료된 item 이벤트는 모두 남긴다. response_item 사본은
    # 이 파일에 대응하는(같은 역할·같은 문장) 완료 item이 없을 때만 남긴다.
    with path.open('r', encoding='utf-8-sig', errors='strict') as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                outer = json.loads(line)
            except ValueError:
                continue
            if not isinstance(outer, dict):
                continue
            if outer.get('type') == 'session_meta':
                pay = outer.get('payload') or {}
                small = {k: pay.get(k) for k in ('id','cwd','originator','cli_version', 'source', 'model_provider','git') if k in pay}
                evidence = source_ref(path, root, digest, f'line={line_number}', 'EXISTING_JSONL_SESSION_META')
                idx.add(tid, 'session_meta', small, evidence,
                        time_entry(outer.get('timestamp'), 'jsonl_session_meta'),
                        source_order=line_number, verification='existing_jsonl',
                        dedup_key=('jsonl_session_meta', str(path), line_number))
                continue
            val = normalize_jsonl_item(outer)
            if val is None:
                continue
            kind, item, timestamp, turn, itemid, ordinal, method = val
            display = display_from_item(item, kind)
            if method == 'response_item_fallback':
                fallback.append((line_number, kind, item, timestamp, turn, itemid, ordinal, display))
                continue
            if method == 'event_completed':
                primary_fingerprints.add((mapped_kind(kind), display))
            evidence = source_ref(path, root, digest, f'line={line_number}', 'EXISTING_JSONL_' + method.upper())
            unique = (tid, mapped_kind(kind), itemid) if itemid and method == 'event_completed' else None
            idx.add(tid, kind, item, evidence,
                    time_entry(timestamp, 'existing_jsonl_item'),
                    turn_id=turn, item_id=itemid, ordinal=ordinal, source_order=line_number,
                    verification='existing_jsonl', is_message=mapped_kind(kind) in ('user_message','agent_message'),
                    dedup_key=unique)
            count += 1
    for line_number, kind, item, timestamp, turn, itemid, ordinal, display in fallback:
        if (mapped_kind(kind), display) in primary_fingerprints:
            continue
        evidence = source_ref(path, root, digest, f'line={line_number}', 'EXISTING_JSONL_RESPONSE_FALLBACK')
        idx.add(tid, kind, item, evidence,
                time_entry(timestamp, 'existing_jsonl_response'),
                turn_id=turn, item_id=itemid, ordinal=ordinal, source_order=line_number,
                verification='existing_jsonl_fallback', is_message=True)
        count += 1
    return count


def ingest_optional_text_logs(directory, targets, idx, root, max_lines=300):
    """명시적 증거: 스레드 하나만 해당하는 로그 줄. 대화 메시지가 아니다."""
    if directory is None or not directory.is_dir():
        return {'files': 0, 'observations': 0}
    patterns = ('*.log', '*.txt')
    paths = sorted(set(p for pattern in patterns for p in directory.rglob(pattern) if p.is_file()))
    result = {'files': 0, 'observations': 0}
    known = set(targets)
    uuid_bytes = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}(?![0-9a-fA-F])')
    for path in paths:
        if path.stat().st_size > 256 * 1024 * 1024:
            continue
        count_by_thread = collections.Counter()
        digest = idx.digest(path)
        result['files'] += 1
        with path.open('r', encoding='utf-8-sig', errors='replace') as handle:
            for line_number, line in enumerate(handle, 1):
                matches = set(x.lower() for x in uuid_bytes.findall(line)) & known
                # 관련 스레드 ID가 여러 개 들어 있는 줄은 어느 스레드의 것인지 입증할 수 없으므로
                # 임의로 귀속하지 않는다.
                if len(matches) != 1:
                    continue
                tid = next(iter(matches))
                if max_lines and count_by_thread[tid] >= max_lines:
                    continue
                count_by_thread[tid] += 1
                m = re.search(r'\b20\d\d-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)\b',line)
                timestamp = time_entry(m.group(0).replace(' ', 'T'), 'explicit_log_timestamp') if m else None
                clean = line.rstrip('\r\n')
                ev = source_ref(path, root, digest, f'line={line_number}', 'TEXT_LOG_OBSERVATION')
                idx.add(tid, 'desktop_log', {'line': clean}, ev, timestamp,
                        source_order=line_number, verification='text_log_observation',
                        notes=['Literal log text only; may describe an event but not a recovered chat message.'])
                result['observations'] += 1
    return result


# 복원 대상 스레드 목록을 정한다 (지정 ID, 삭제 표시, 구조 레코드, 입력 기록 등)
def discover_threads(args, root, dbs, markers, projectless, indexed, existing, prompt_catalog):
    if args.thread_id:
        tid = args.thread_id.lower()
        if not UUID.fullmatch(tid):
            raise ValueError('--thread-id must be an exact 36-character UUID.')
        return [tid], set()
    typed = set()
    if args.scope == 'all':
        # 넓은 탐색은 로컬 스레드가 들어 있는 DB로만 제한한다. 카탈로그 DB에는 관련 없는
        # 원격/ChatGPT UUID가 수천 개 있을 수 있어 로컬 포렌식 조사가 끝없이 커진다.
        local_dbs = [p for p in dbs if v5_db_family(p) in ('state','history','logs')]
        typed = discover_structured(root, local_dbs)
    chosen = set(markers)
    if args.scope == 'all':
        chosen |= set(projectless) | typed | set(indexed) | set(prompt_catalog) | set(existing)
    if not chosen:
        raise ValueError('No matching thread candidates: use --thread-id or --scope all.')
    priority = lambda tid: (0 if tid in markers else 1 if tid in projectless else 2, tid)
    chosen = sorted(chosen, key=priority)
    if args.max_threads:
        chosen = chosen[:args.max_threads]
    return chosen, typed


# Global 입력 기록(prompt-history)을 복원 색인에 추가 (출처 파일·JSON 경로 근거 포함, 시각 없음)
def ingest_global_records(root, catalog, targets, idx):
    for tid in targets:
        for prompt in catalog.get(tid, []):
            evidences = []
            for src in prompt['sources']:
                p = root / src['file']
                evidences.append(source_ref(p, root, src['sha256'], src['json_path'], 'GLOBAL_PROMPT_HISTORY'))
            if not evidences:
                continue
            rec = idx.add(tid, 'prompt_history', {'text': prompt['text'],
                                                'prompt_history_index': prompt['index']},
                          evidences[0], timestamp=None, source_order=prompt['index'],
                          verification='global_prompt_history',
                          notes=['Composer history; no per-prompt timestamp or independently verified send event.'],
                          dedup_key=('GLOBAL_PROMPT_HISTORY', tid, prompt['index'], prompt['text']))
            for e in evidences[1:]:
                if e not in rec['evidence']:
                    rec['evidence'].append(e)


# 복원된 스레드 메타데이터의 첫 사용자 메시지를 '첫 입력 참조' 레코드로 추가 (가장 신뢰도 높은 출처 하나)
def add_first_input_references(idx):
    # 복원된 threads 테이블의 첫 프롬프트는 메타데이터이지 시각이 있는 userMessage 항목이 아니다.
    # 출처만 연결하고 시각은 '알 수 없음'으로 둔다.
    best = {}
    weights = {'sqlite_active_main_db': 0, 'sqlite_recovered_freelist_cell': 1,
               'sqlite_recovered_residual_cell': 2, 'wal_checksum_valid': 3}
    for e in list(idx.records):
        if e['kind'] != 'thread_metadata' or not isinstance(e['raw'], dict):
            continue
        text = e['raw'].get('first_user_message')
        if not isinstance(text, str) or not text.strip():
            continue
        key = (e['thread_id'], text)
        if key not in best or weights.get(e['verification'], 50) < weights.get(best[key]['verification'], 50):
            best[key] = e
    for (tid, text), meta in best.items():
        idx.add(tid, 'first_input_reference', {'text': text,
                 'associated_thread_creation_timestamp': meta['timestamp']},
                meta['evidence'][0], timestamp=None,
                verification='sqlite_first_user_message_metadata',
                notes=['Recovered first-user-message metadata, NOT an independent timestamped userMessage event.'],
                dedup_key=('FIRST_INPUT_METADATA', tid, text))


def sort_key(e):
    """시각 있는 이벤트를 먼저 둔다. 나머지 묶음은 아티팩트 간 시간 순서가 없다."""
    if e['timestamp'] is not None:
        return (0, e['timestamp']['utc'], e.get('ordinal') if isinstance(e.get('ordinal'), int) else 10**15, e['event_id'])
    if e['kind'] == 'first_input_reference':
        # 의미상 첫 입력 표시 (만들어 낸 이벤트 시각이 아님)
        return (1, 0, '', 0, e['event_id'])
    if e['kind'] == 'prompt_history':
        return (1, 1, '', e['source_order'] if isinstance(e.get('source_order'), int) else 10**15, e['event_id'])
    # 출처 내부 순서 힌트는 시각이 아니므로 검증된 시간 순서와 섞지 않는다.
    # 다른 파일끼리는 일부러 순번으로 정렬하지 않는다.
    file_key = e['evidence'][0]['file'] if e['evidence'] else ''
    return (1, 2, file_key, e.get('source_order') if isinstance(e.get('source_order'), int) else 10**15, e['event_id'])


# 스레드 하나의 세션 요약 (제목, 첫 입력, 생성/수정 시각, 건수, 복원 완전성)
def calculate_session(tid, entries, markers, indexed, existing):
    metadata = [e for e in entries if e['kind'] == 'thread_metadata']
    by_quality = {'sqlite_active_main_db': 0, 'sqlite_recovered_freelist_cell': 1,
                  'sqlite_recovered_residual_cell': 2, 'wal_checksum_valid': 3}
    metadata.sort(key=lambda e: by_quality.get(e['verification'], 10))
    meta = metadata[0]['raw'] if metadata else {}
    title = (meta.get('title') if isinstance(meta, dict) else None) or indexed.get(tid, {}).get('title')
    first_input = meta.get('first_user_message') if isinstance(meta, dict) else None
    raw_created = meta.get('created_at') if isinstance(meta, dict) else None
    raw_updated = meta.get('updated_at') if isinstance(meta, dict) else None
    created = time_entry(raw_created, 'sqlite_thread_creation') if raw_created else None
    updated = time_entry(raw_updated, 'sqlite_thread_update') if raw_updated else None
    if created is None:
        metas = [e for e in entries if e['kind'] == 'session_meta' and e['timestamp']]
        if metas: created = sorted(metas, key=sort_key)[0]['timestamp']
    first_input_refs = sum(x['kind']=='first_input_reference' for x in entries)
    known_inputs = sum(x['kind']=='user_message' for x in entries)
    known_answers = sum(x['kind']=='agent_message' for x in entries)
    prompt_history_count = sum(x['kind']=='prompt_history' for x in entries)
    tool_count = sum(x['kind'] in ('command_execution','mcp_tool_call','web_search', 'file_change','function_call','custom_tool_call') for x in entries)
    has_messages = known_inputs + known_answers > 0
    if has_messages: status = 'PARTIAL_MESSAGES_RECOVERED_COMPLETENESS_UNPROVEN'
    elif prompt_history_count or first_input_refs: status = 'PROMPT_HISTORY_OR_METADATA_ONLY'
    elif entries: status = 'METADATA_OR_LOG_ONLY'
    else: status = 'NO_STRUCTURED_CONTENT'
    log_text = [str(x['display_text'] or '') for x in entries if x['kind'] in ('runtime_log', 'desktop_log')]
    # 로그의 텍스트 언급은 관측일 뿐, 이 증거 집합에서 특정 삭제가 완료됐다는 독립 증거가 아니다.
    delete_request_observed = any('thread/delete' in msg for msg in log_text)
    delete_completion_observed = any('thread/deleted' in msg for msg in log_text)
    return {
        'observed_delete_request_in_logs': delete_request_observed,
        'observed_delete_completion_in_logs': delete_completion_observed,
        'log_deletion_event_attribution_requires_manual_review': True,
        'session_id': tid, 'thread_id': tid, 'deleted_marker_found': tid in markers,
        'deleted_marker_is_independent_deletion_proof': False,
        'existing_jsonl_files': [str(p) for p in existing.get(tid, [])],
        'title': title, 'first_user_message_metadata': first_input,
        'created_at': created, 'updated_at': updated,
        'cwd': meta.get('cwd') if isinstance(meta, dict) else None,
        'historical_rollout_path': meta.get('rollout_path') if isinstance(meta, dict) else None,
        'rollout_path_is_existing_file_proof': False,
        'recovery_status': status,
        'counts': {'structured_user_messages':known_inputs, 'structured_agent_messages':known_answers,
                   'global_prompt_history_entries':prompt_history_count,
                   'first_user_message_metadata_references':first_input_refs,
                   'tool_action_records':tool_count,
                   'total_events':len(entries),
                   'timestamped_events':sum(x['timestamp'] is not None for x in entries),
                   'untimed_events':sum(x['timestamp'] is None for x in entries)},
        'event_ids_in_report_order': [e['event_id'] for e in entries]
    }


# 시각 항목을 KST 문자열로 (없으면 '시간 확인 불가')
def compact_date(t):
    return t['kst'].replace('T', ' ') if t else '시간 확인 불가'


# 복원 이벤트의 보고서 표시 문장 (입력 기록/메타데이터 등은 주의 표시를 붙임)
def event_display(e):
    if e['kind'] == 'first_input_reference':
        return '[SQLite first_user_message 참조; 개별 입력 시간은 미확인] ' + (e['display_text'] or '')
    if e['kind'] == 'prompt_history':
        return '[Global prompt-history, 발송·시간 미검증] ' + (e['display_text'] or '')
    if e['kind'] == 'thread_metadata':
        raw = e['raw']
        return '[SQLite 스레드 메타데이터] title=' + repr(raw.get('title')) + ', first_user_message=' + repr(raw.get('first_user_message'))
    if e['kind'] == 'catalog_metadata':
        return '[카탈로그 메타데이터] ' + str(e['display_text'] or '')
    return e['display_text'] or json.dumps(e['raw'], ensure_ascii=False, default=str)


# V4 복원 결과를 사람이 읽는 한글 TXT 보고서로 쓴다
def write_human_txt(path, model, show_logs=False, max_chars=1500):
    events_by_id = {e['event_id']:e for e in model['events']}
    with path.open('w', encoding='utf-8-sig', newline='\n') as f:
        f.write('ACTF CODEX 복원 결과 (인코딩: UTF-8 BOM / 기준 시간대: KST)\n')
        f.write('주의: 타임스탬프 없는 프롬프트에는 시간을 생성하지 않습니다. 완전 복원은 보장되지 않습니다.\n')
        f.write('원본 증거: 분석용 사본 사용 권장. 원본에 쓰기 작업을 하지 마세요.\n\n')
        for session in model['sessions']:
            f.write('='*90 + '\n')
            f.write('스레드 ID: '+session['thread_id']+'\n')
            f.write('제목: '+str(session['title'] or '미확인')+'\n')
            f.write('스레드 생성 시각: '+ compact_date(session['created_at'])+'\n')
            f.write('스레드 수정 시각: '+ compact_date(session['updated_at'])+'\n')
            f.write('삭제 표시: '+str(session['deleted_marker_found'])+' (삭제 완료의 독립적 증거는 아님)\n')
            f.write('복원 상태: '+session['recovery_status']+'\n')
            f.write('건수: '+json.dumps(session['counts'], ensure_ascii=False)+'\n')
            if session['historical_rollout_path']:
                f.write('원본 JSONL의 과거 경로(현재 존재를 뜻하지 않음): '+str(session['historical_rollout_path'])+'\n')
            entries = [events_by_id[x] for x in session['event_ids_in_report_order']]
            timed = [e for e in entries if e['timestamp'] is not None and (show_logs or e['kind'] not in ('runtime_log','desktop_log'))]
            untimed = [e for e in entries if e['timestamp'] is None and (show_logs or e['kind'] not in ('runtime_log','desktop_log'))]
            for label, group in [('확인된 시간 기반 배열 (시간 동일 시 원순서 미검증)', timed),
                                 ('개별 시간 없음 (원본 파일·배열 내 순서만 유지)', untimed)]:
                f.write('\n--- '+label+' ---\n')
                if not group: f.write('(해당 없음)\n')
                for e in group:
                    f.write('\n['+e['kind']+'] '+compact_date(e['timestamp'])+' / '+e['verification']+'\n')
                    if e['turn_id']:
                        f.write('  turn_id='+str(e['turn_id'])+'\n')
                    if e['kind'] == 'prompt_history':
                        f.write('  prompt-history 내부 배열 인덱스: '+str(e['source_order'])+' (시각을 뜻하지 않음)\n')
                    data = event_display(e)
                    # 사람용 파일에서는 아주 긴 도구 출력을 줄여 보여줄 수 있지만,
                    # 메모리에 돌려주는 레코드는 복원한 원본 페이로드 전체를 보존한다.
                    if max_chars > 0 and len(data) > max_chars:
                        data = data[:max_chars] + '\n...[표시용 텍스트만 축약됨; --max-text-chars 0 사용 시 전체 표시]'
                    f.write('  '+data.replace('\n','\n  ')+'\n')
                    for ev in e['evidence']:
                        f.write('  증거='+str(ev['file'])+' / '+str(ev['method'])+' / '+str(ev.get('location'))+'\n')
            f.write('\n')


# 검증 전 UUID 위치/조각 진단 파일을 쓴다 (복원된 메시지가 아님)
def write_diagnostics(path, diagnostic):
    # 읽기용 보고서에는 깨진 바이트를 넣지 않는다. 이 선택형 진단 파일에서는
    # 해석 불가 문자(U+FFFD)를 "�" 대신 \\ufffd 문자열로 표시한다.
    lines = ['DIAGNOSTIC: These UUID positions/fragments are NOT restored messages.']
    for entry in diagnostic:
        lines.append('\nfile='+entry['file']+' type='+entry['type'])
        for tid, values in entry['items'].items():
            lines.append('thread_id='+tid)
            for s in values:
                lines.append('  '+str(s).encode('ascii','backslashreplace').decode('ascii'))
    path.write_text('\n'.join(lines)+'\n', encoding='utf-8-sig')


# V4 독립 복원 도구 실행 (명령줄 인자 해석 -> 대상 탐색 -> DB 조사 -> 보고서)
def run_recovery(args=None, write_reports=True):
    standalone = args is None
    if standalone:
        enable_unicode_output()
    ap = argparse.ArgumentParser(description='ACTF Codex independent recovery-only tool; Korean TXT/HTML reports and optional RAW diagnostics.')
    ap.add_argument('--codex-home', type=Path, required=True, help='Acquired, preferably immutable .codex COPY')
    ap.add_argument('--output-dir', type=Path, default=Path('Codex_Recovery_Result'))
    ap.add_argument('--scope', choices=('markers','all'), default='all',
                    help='all=markers+global+structured SQLite+session index+present JSONL; markers=deletion markers only')
    ap.add_argument('--thread-id', help='Optional exact UUID; overrides scope')
    ap.add_argument('--include-existing-jsonl', dest='no_existing_jsonl', action='store_false', default=True,
                    help='Also read currently present JSONL for cross-check (disabled by default: this is recovery-only)')
    ap.add_argument('--no-existing-jsonl', dest='no_existing_jsonl', action='store_true',
                    help='Do not parse currently present JSONL (default; kept for compatibility)')
    ap.add_argument('--logs-dir', type=Path, help='Optional separately acquired Desktop logs directory, e.g. LocalCache/Local/Codex/Logs')
    ap.add_argument('--recovered-jsonl-dir', type=Path, help='Optional already-recovered JSONL folder; does not carve disk images')
    ap.add_argument('--fragments', action='store_true', help='Write unverified byte fragments into separate diagnostic file only')
    ap.add_argument('--max-hits', type=int, default=10, help='UUID leads per thread/DB; 0=do not record')
    ap.add_argument('--max-log-lines', type=int, default=300, help='Maximum text-log observations per thread/file; 0=unlimited')
    ap.add_argument('--carve-max-per-page', type=int, default=25, help='Cap validated residual cells per page; 0=unlimited (slower)')
    ap.add_argument('--max-threads', type=int, default=0, help='Optional cap; 0=all discovered in scope')
    ap.add_argument('--max-text-chars', type=int, default=0, help='Optional display cap in TXT/HTML; 0=entire text; internal recovery values retain full content')
    ap.add_argument('--show-logs', action='store_true', help='Include logs in human-readable TXT/HTML (always included in in-memory result)')
    if args is None:
        args = ap.parse_args()
    root = Path(args.codex_home).resolve()
    output = Path(args.output_dir).resolve() if write_reports else None
    if not root.is_dir(): raise ValueError('Evidence folder does not exist: '+str(root))
    if write_reports and (output == root or root in output.parents):
        raise ValueError('Output directory MUST be outside the evidence directory to prevent evidence modification.')
    if args.max_hits < 0 or args.max_log_lines < 0 or (0 < args.max_text_chars < 100) or args.max_threads < 0 or args.carve_max_per_page < 0:
        raise ValueError('Limits cannot be negative; --max-text-chars is 0 or >= 100')
    if args.logs_dir and not args.logs_dir.is_dir():
        raise ValueError('Supplied --logs-dir does not exist: '+str(args.logs_dir))
    if args.recovered_jsonl_dir and not args.recovered_jsonl_dir.is_dir():
        raise ValueError('Supplied --recovered-jsonl-dir does not exist: '+str(args.recovered_jsonl_dir))

    # 기본은 복원 전용: 현재 JSONL은 명시적으로 켜지 않으면 제외한다.
    # 메인 DB/WAL은 변경 불가 원시 증거로 연다. 일반 SQLite 연결로 증거 사본을 수정하거나
    # 자동 체크포인트하지 않는다.
    markers, projectless = load_global_catalog(root, quiet=not standalone)
    catalog = load_global_prompt_history(root, quiet=not standalone)
    indexed = load_simple_index(root)
    existing = discover_existing_jsonl(root) if not args.no_existing_jsonl else {}
    if args.recovered_jsonl_dir:
        # 따로 복원한 파일 사본은 이름이 다를 수 있다.
        # 파일명에 Codex Rollout UUID가 없으면 앞쪽 몇 레코드의 session_meta ID가 필요하다.
        supplied = discover_existing_jsonl(args.recovered_jsonl_dir)
        for p in args.recovered_jsonl_dir.rglob('*.jsonl'):
            if any(p in paths for paths in supplied.values()): continue
            try:
                with p.open('r', encoding='utf-8-sig', errors='strict') as fh:
                    for _ in range(5):
                        line = fh.readline()
                        if not line: break
                        item = json.loads(line)
                        if item.get('type') == 'session_meta':
                            pl = item.get('payload') or {}
                            tid = pl.get('id') or pl.get('session_id')
                            if isinstance(tid, str) and UUID.fullmatch(tid):
                                supplied.setdefault(tid.lower(), []).append(p)
                            break
            except (OSError, ValueError, UnicodeDecodeError, AttributeError):
                pass
        for tid, paths in supplied.items():
            existing.setdefault(tid, []).extend(paths)
    dbs = db_files(root)
    targets, typed = discover_threads(args, root, dbs, markers, projectless, indexed, existing, catalog)
    targetset = set(targets)
    if standalone:
        print('[ACTF] '+str(len(targets))+' threads; '+str(len(dbs))+' SQLite DBs. Existing JSONL files: '+str(sum(len(v) for v in existing.values())))
        print('[ACTF] 복원 전용: 현재 JSONL 기본 제외; 삭제 대화 전체 복원을 보장하지 않습니다.')
    idx = RecoveryIndex(root, {})
    diagnostic = []
    dbstats = []
    ingest_global_records(root, catalog, targets, idx)
    for tid in targets:
        if tid in indexed:
            x = indexed[tid]; p = root/'session_index.jsonl'
            idx.add(tid, 'catalog_metadata', {'title':x.get('title'), 'source':'session_index.jsonl'},
                    source_ref(p, root, idx.digest(p), 'line='+str(x['source_index_line']), 'SESSION_INDEX'),
                    time_entry(x.get('updated_at'), 'session_index_updated_at'),
                    source_order=x['source_index_line'],verification='session_index_catalog')
    for db in dbs:
        if standalone: print('[SCAN] '+str(db.relative_to(root)), flush=True)
        try:
            stats = decode_sqlite_evidence(db,targetset,idx,root,args.fragments,args.max_hits,diagnostic,args.carve_max_per_page)
            dbstats.append({'file':str(db.relative_to(root)), **stats})
        except (sqlite3.DatabaseError, OSError, ValueError, MemoryError) as exc:
            dbstats.append({'file':str(db.relative_to(root)), 'scan_error':str(exc)})
            if standalone: print('[WARN] DB skipped: '+db.name+' ('+str(exc)+')', file=sys.stderr)
    add_first_input_references(idx)
    jsonl_stats = []
    for tid in targets:
        for path in existing.get(tid, []):
            if standalone:
                try: shown_path = str(path.relative_to(root))
                except ValueError: shown_path = str(path)
                print('[JSONL] '+shown_path, flush=True)
            try:
                count = ingest_existing_jsonl(path, tid, idx, root)
                try: label = str(path.relative_to(root))
                except ValueError: label = str(path)
                jsonl_stats.append({'file':label, 'items':count})
            except (UnicodeDecodeError, OSError) as exc:
                try: label = str(path.relative_to(root))
                except ValueError: label = str(path)
                jsonl_stats.append({'file':label, 'error':str(exc)})
    if args.logs_dir:
        log_stats = ingest_optional_text_logs(args.logs_dir, targetset, idx, root, max_lines=args.max_log_lines)
    else:
        log_stats = {'files':0,'observations':0}

    by_thread = defaultdict(list)
    for entry in idx.records:
        if entry['thread_id'] in targetset:
            by_thread[entry['thread_id']].append(entry)
    sessions, ordered_events = [], []
    for tid in targets:
        entries = sorted(by_thread.get(tid, []), key=sort_key)
        sessions.append(calculate_session(tid, entries, markers, indexed, existing))
        ordered_events.extend(entries)
    # 분석 시점에 파일 목록의 해시를 기록한다. 결과는 증거 폴더 *밖*에 저장한다.
    manifest = []
    for name in ('.codex-global-state.json','.codex-global-state.json.bak','session_index.jsonl'):
        f = root/name
        if f.is_file():
            manifest.append({'file':str(f.relative_to(root)), 'sha256':idx.digest(f), 'size':f.stat().st_size})
    for f in dbs:
        manifest.append({'file':str(f.relative_to(root)), 'sha256':idx.digest(f),'size':f.stat().st_size})
        wp = Path(str(f)+'-wal')
        if wp.is_file(): manifest.append({'file':str(wp.relative_to(root)), 'sha256':idx.digest(wp),'size':wp.stat().st_size})
        shm = Path(str(f) + '-shm')
        if shm.is_file():
            manifest.append({'file':str(shm.relative_to(root)), 'sha256':idx.digest(shm),
                             'size':shm.stat().st_size,
                             'note':'SQLite WAL-index sidecar fingerprint only; no standalone message attribution'})
    for paths in existing.values():
        for f in paths:
            if f.is_file():
                try: label = str(f.resolve().relative_to(root))
                except ValueError: label = str(f.resolve())
                manifest.append({'file':label, 'sha256':idx.digest(f),'size':f.stat().st_size})
    model = {
        'format_version': V4_FORMAT,
        'generated_at_utc':datetime.now(timezone.utc).isoformat(),
        'time_display_zone':'Asia/Seoul',
        'scope':{'mode':args.scope, 'explicit_thread_id':args.thread_id,
                 'existing_jsonl_scanned':not args.no_existing_jsonl,
                 'external_desktop_logs_scanned':bool(args.logs_dir),
                 'supplied_recovered_jsonl_scanned':bool(args.recovered_jsonl_dir)},
        'limitations':V4_LIMITATIONS,
        'source_metadata': {'source_directory':str(root),'files':manifest,
                            'db_scan_stats':dbstats, 'existing_jsonl_stats':jsonl_stats,
                            'text_log_stats':log_stats,
                            'unverified_raw_diagnostics_file':'04_RAW_진단.txt' if write_reports and diagnostic else None},
        'sessions':sessions,
        'events':ordered_events,
        'unverified_raw_diagnostics':diagnostic if args.fragments and not write_reports else [],
    }
    if write_reports:
        output.mkdir(parents=True, exist_ok=True)
        write_human_txt(output/'02_스레드별_복원내용.txt',model,args.show_logs,args.max_text_chars)
        diag_path = output/'04_RAW_진단.txt'
        if diagnostic:
            write_diagnostics(diag_path,diagnostic)
        elif diag_path.exists():
            diag_path.unlink()  # 이전 진단 파일을 이번 실행 결과로 착각하지 않도록 한다.
        with (output/'01_전체_요약.txt').open('w',encoding='utf-8-sig',newline='\n') as f:
            f.write('ACTF CODEX OFFLINE RECOVERY / KST DISPLAY\n')
            f.write('확보되지 않은 전체 대화를 생성하지 않으며, 복원 결과의 완전성을 보장하지 않습니다.\n')
            f.write('건수: 스레드='+str(len(sessions))+' / 이벤트='+str(len(ordered_events))+'\n')
            for s in sessions:
                c=s['counts']
                f.write('\n'+s['thread_id']+' | 생성='+compact_date(s['created_at'])+'\n')
                f.write('  상태='+s['recovery_status']+' / 최초 입력='+repr(s['first_user_message_metadata'])+'\n')
                f.write(f"  구조화된 user={c['structured_user_messages']}, agent={c['structured_agent_messages']}, "
                        f"Global 프롬프트={c['global_prompt_history_entries']}, 도구={c['tool_action_records']}, "
                        f"시간 없음={c['untimed_events']}\n")
        print('[OK] Output: '+str(output))
        print('[OK] 한글 TXT (UTF-8 BOM), HTML (UTF-8), 선택적 RAW 진단 파일 생성. JSON/CSV 미생성.')
        print('[OK] Threads='+str(len(sessions))+' Events='+str(len(ordered_events)))
        print('[NOTICE] Unknown timestamps remain NULL; fragments are unverified diagnostics.')
    return model




# ==================== ACTF V5 차이 기반 복원 ====================

# V5: 위 V4 함수들은 바이트 단위 포렌식 엔진이다. 이 진입점은 일부러 *분리*되어 있으며,
# Rollout이 없는 스레드만 보고서에 들어갈 수 있다.
# '모든 SQLite' 일반 검색은 하지 않는다. 관측 데이터에서 쓸모 있는 증거가 나온 DB는 이 4개이며,
# 관련 없는 원격 카탈로그 행은 로컬 스레드가 아니다.
V5_DB = ('state_*.sqlite', 'thread_history_*.sqlite', 'logs_*.sqlite', 'codex-dev.db')
V5_VERSION = 'actf-codex-deleted-recovery-v5'
V5_UUID_IN_TEXT = re.compile(
    r'(?<![0-9a-fA-F])[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}(?![0-9a-fA-F])')
V5_DELETE_REQ = re.compile(r'(?<![a-zA-Z])thread/delete(?![a-zA-Z/])', re.I)
V5_DELETE_DONE = re.compile(r'(?<![a-zA-Z])thread/deleted(?![a-zA-Z/])', re.I)
V5_ARCHIVE_REQ = re.compile(r'(?<![a-zA-Z])thread/archive(?![a-zA-Z/])', re.I)
V5_ARCHIVE_DONE = re.compile(r'(?<![a-zA-Z])thread/archived(?![a-zA-Z/])', re.I)


def v5_rollout_inventory(root):
    """실제 두 폴더(sessions, archived_sessions)를 조사한다. 옛 DB 문자열에 있는 경로는 세지 않는다.

    가능하면 session_meta(최대 25개 레코드)를 읽는다. 애매하거나 손상된 기존 파일도
    그 파일명 UUID에 대해 '없음(삭제)' 판정을 막는다.
    """
    folders = {'normal': root/'sessions', 'archived': root/'archived_sessions'}
    records, errors = defaultdict(lambda: {'normal': [], 'archived': []}), []
    for status, folder in folders.items():
        if not folder.is_dir():
            errors.append(f'MISSING_COLLECTION: {folder}; deletion cannot be conclusively assessed')
            continue
        for file in sorted(folder.rglob('*.jsonl')):
            if not file.is_file():
                continue
            filename_match = re.search(
                r'([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})\.jsonl$',file.name)
            filename_tid = filename_match.group(1).lower() if filename_match else None
            embedded_tid = None
            try:
                with file.open('r', encoding='utf-8-sig', errors='strict') as handle:
                    for _ in range(25):
                        line = handle.readline()
                        if not line:
                            break
                        try:
                            row = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(row,dict) and row.get('type')=='session_meta':
                            payload = row.get('payload') or {}
                            tid = payload.get('id') or payload.get('session_id')
                            if isinstance(tid,str) and UUID.fullmatch(tid):
                                embedded_tid = tid.lower()
                            break
            except (OSError,UnicodeDecodeError) as ex:
                errors.append(f'UNREADABLE_ROLLOUT: {file}: {ex}; path still exists')
            if filename_tid and embedded_tid and filename_tid!=embedded_tid:
                errors.append(f'CONFLICTING_ROLLOUT_ID: {file} filename={filename_tid} meta={embedded_tid}')
            # 불일치 때문에 존재하는 파일을 삭제로 분류하지 않는 쪽을 택한다.
            for tid in set(x for x in (filename_tid,embedded_tid) if x):
                records[tid][status].append(str(file))
    return dict(records), errors


def v5_catalog_refs(db_path, known):
    """메인 DB 카탈로그는 뒷받침 용도로만 쓴다. 계정 전체의 수천 개 원격 ChatGPT 카탈로그 행을
    누락된 로컬 Codex 대화로 취급하지 않는다. source_kind=vscode 일부는 수집본의 로컬 대화다.
    """
    found, details = set(), defaultdict(list)
    if not db_path.is_file():
        return found, details
    try:
        with main_db_conn(db_path) as conn:
            tabs={x[0] for x in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'local_thread_catalog' not in tabs:
                return found, details
            cols={x[1] for x in conn.execute('PRAGMA table_info(local_thread_catalog)')}
            if not {'thread_id','source_kind'}.issubset(cols):
                return found, details
            namecol='display_title' if 'display_title' in cols else "''"
            for tid,kind,title in conn.execute(
                f'SELECT thread_id,source_kind,{namecol} FROM local_thread_catalog'):
                if not isinstance(tid,str) or not UUID.fullmatch(tid):
                    continue
                tid=tid.lower()
                if kind=='vscode':
                    found.add(tid)
                if tid in known or kind=='vscode':
                    details[tid].append({'source_kind':kind,'title':title,
                                         'source':str(db_path)})
    except (sqlite3.Error,OSError):
        pass
    return found,details



def v5_state_archive_snapshot(root, targets):
    """현재 SQLite 스레드 플래그(보관 여부 등)는 스냅샷일 뿐 삭제 행위의 증거가 아니다."""
    p=v5_select_db(root,'state')
    result={}
    if not p.is_file():return result
    try:
        with main_db_conn(p) as conn:
            tables={x[0] for x in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if 'threads' not in tables:return result
            cols={x[1] for x in conn.execute('PRAGMA table_info(threads)')}
            names=['id']+[x for x in ('archived','archived_at','rollout_path','title') if x in cols]
            for row in conn.execute('SELECT '+','.join(names)+' FROM threads'):
                obj=dict(zip(names,row));tid=obj.get('id')
                if isinstance(tid,str) and tid.lower() in targets:
                    result[tid.lower()]={k:safe_jsonable(v) for k,v in obj.items() if k!='id'}
    except (sqlite3.Error,OSError):pass
    return result


def v5_historical_log_observations(root, targets, max_cells=15):
    """복원 대상을 고르기 전에, 검증된 구조의 과거 LOGS SQLite 항목을 조사한다.
    프리리스트/WAL 행은 *앱의 대화*가 삭제됐거나 WAL 트랜잭션이 커밋됐다는 증거가 아니다.
    """
    db=v5_select_db(root,'logs');out=defaultdict(list)
    if not db.is_file() or not targets:return out
    try:
        digest=sha_file(db)
        # 빠른 사전 선택: 손상되지 않은 프리리스트 리프와 체크섬이 맞는 WAL만 본다.
        # 잔여 셀 카빙은 선택된 대상에 대해 나중에 한 번만 한다. 원시 UUID로만 발견된 후보마다
        # 반복하면 비용이 너무 크고 삭제 상태의 믿을 만한 증거도 늘지 않는다.
        found,_,_=main_db_freelist(db,targets)
        wal=Path(str(db)+'-wal')
        if wal.is_file():
            events,_=wal_events(wal,targets,max_hints=0)
            found.extend(events)
        for item in found:
            if item.get('kind')!='runtime_log':continue
            payload=item.get('payload') or {}
            txt=' '.join(str(x or '') for x in (payload.get('target'),payload.get('feedback_log_body')))
            kind=v5_log_event_type(txt)
            tid=item.get('thread_id')
            if kind and tid in targets:
                src=wal if str(item.get('method','')).startswith('WAL') else db
                out[tid].append({'type':kind,'source':str(src.relative_to(root)),
                    'record':str(item.get('location')),'time':time_entry(item.get('timestamp'),'sqlite_historical_log'),
                    'source_sha256':sha_file(src) if src!=db else digest,
                    'excerpt':txt[:800],'attribution':'structured_historical_log_thread_id',
                    'historical_storage_method':item.get('method'),
                    'reviewed_transaction':False})
    except (sqlite3.Error,OSError,ValueError,MemoryError) as err:
        print('[WARN] historical logs unavailable:',str(err),file=sys.stderr)
    return out


def v5_log_event_type(text):
    """프로토콜 형태와 정확히 같은 토큰만 인정한다. 텍스트 언급은 관측일 뿐,
    실제 RPC 성공이나 사람의 행위를 자동으로 확인하지 않는다.
    """
    if V5_DELETE_DONE.search(text): return 'delete_completion_token'
    if V5_DELETE_REQ.search(text): return 'delete_request_token'
    if V5_ARCHIVE_DONE.search(text): return 'archive_completion_token'
    if V5_ARCHIVE_REQ.search(text): return 'archive_request_token'
    return None


def v5_observations(root, logs_dir, targets):
    """로그 메인 DB와 보조 Desktop 로그에서 스레드에 귀속되는 삭제/보관 토큰을 찾는다.
    주변 줄이나 익명 완료 이벤트에서 ID를 가져오지 않는다.
    앱의 실제 삭제 거래인지(디버그/인용/프롬프트 언급이 아닌지)는 로그 원문을 따로 검토해야 한다.
    """
    out=defaultdict(list)
    db=v5_select_db(root,'logs')
    if db.is_file():
        try:
            digest=sha_file(db)
            with main_db_conn(db) as conn:
                cols={x[1] for x in conn.execute('PRAGMA table_info(logs)')}
                if {'id','thread_id','feedback_log_body'}.issubset(cols):
                    for rid,ts,tid,body,target in conn.execute(
                        'SELECT id,ts,thread_id,feedback_log_body,target FROM logs'):
                        text=' '.join(str(x or '') for x in (target,body))
                        kind=v5_log_event_type(text)
                        if not kind: continue
                        # thread_id가 비어 있으면, 그 이벤트 자체의 텍스트에 있는 *유일한 ID*일 때만 귀속한다.
                        typed=tid.lower() if isinstance(tid,str) and UUID.fullmatch(tid) else None
                        literal=set(t.lower() for t in V5_UUID_IN_TEXT.findall(text))&targets
                        matched=({typed} if typed in targets else set())
                        if not matched and len(literal)==1:
                            matched=literal
                        if len(matched)!=1:
                            continue
                        selected=next(iter(matched))
                        if literal and selected not in literal:
                            continue
                        out[selected].append({'type':kind,'source':str(db.relative_to(root)),'record':str(rid),
                            'time':time_entry(ts,'sqlite_log_ts'), 'source_sha256':digest,
                            'excerpt':text[:800], 'attribution':'event_thread_id_or_unique_literal',
                            'reviewed_transaction':False})
        except (sqlite3.Error,OSError):
            pass
    if logs_dir and logs_dir.is_dir():
        for file in sorted(set(p for pat in ('*.log','*.txt') for p in logs_dir.rglob(pat) if p.is_file())):
            if file.stat().st_size>256*1024*1024: continue
            digest=sha_file(file)
            with file.open('r',encoding='utf-8-sig',errors='replace') as f:
                for number,line in enumerate(f,1):
                    kind=v5_log_event_type(line)
                    if not kind:continue
                    hits=set(t.lower() for t in V5_UUID_IN_TEXT.findall(line))&targets
                    if len(hits)!=1: continue
                    tid=next(iter(hits))
                    match=re.search(r'\b20\d\d-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)\b',line)
                    stamp=time_entry(match.group(0).replace(' ','T'),'explicit_log_timestamp') if match else None
                    out[tid].append({'type':kind,'source':str(file),'record':'line='+str(number),
                        'time':stamp,'source_sha256':digest,'excerpt':line.rstrip()[:800],
                        'attribution':'single_thread_id_same_line','reviewed_transaction':False})
    return out


# 스레드 하나의 삭제 판정 -- Rollout 존재 여부, 삭제/보관 로그, Global 표시, 현재 보관 상태로 분류하고 복원 대상 여부를 정한다
def v5_assess(tid, files, marker, observations, inventory_errors, state_snapshot=None):
    if files.get('normal') or files.get('archived'):
        if files.get('normal') and files.get('archived'):
            return 'PRESENT_BOTH_REVIEW','일반/아카이브 양쪽 존재(확인 필요)',False
        return ('EXISTING_NORMAL','기존 일반 대화',False) if files.get('normal') else (
            'EXISTING_ARCHIVED','아카이브 대화',False)
    kinds={o['type'] for o in observations}
    has_delete='delete_completion_token' in kinds
    request='delete_request_token' in kinds
    has_archive=bool({'archive_completion_token','archive_request_token'}&kinds)
    state_archived=bool((state_snapshot or {}).get('archived'))
    has_archive=has_archive or state_archived
    # 수집 폴더가 없으면 '파일 없음' 판정의 근거가 약해진다.
    folder_missing=any(x.startswith('MISSING_COLLECTION:') for x in inventory_errors)
    if folder_missing:
        return 'COLLECTION_INCOMPLETE','폴더 수집 누락·삭제 판정 보류',False
    if has_delete:
        return 'DELETE_COMPLETION_TOKEN','삭제 완료 로그 토큰 발견(거래 검토 필요)',True
    if has_archive and marker:
        return 'ARCHIVE_PLUS_GLOBAL_MARKER','보관 이력 + Global 삭제 관련 표시(삭제 의심·이력 경합)',True
    if has_archive and not request:
        return 'ARCHIVE_HISTORY_MISSING','보관 이력 존재·현재 Rollout 없음(원인 미확정)',False
    if request and marker:
        return 'DELETE_REQUEST_AND_MARKER','삭제 요청 + Global 표시(완료 미확인)',True
    if request:
        return 'DELETE_REQUEST_ONLY','삭제 요청 발견(완료 미확인)',True
    if marker:
        return 'GLOBAL_MARKER_ONLY','Global 삭제 관련 표시(삭제 의심)',True
    return 'MISSING_UNKNOWN','Rollout 부재·삭제 근거 없음(원인 불명)',False


def v5_recover(argv=None, write_reports=True):
    """V5 복원을 실행해 세션/이벤트 사전을 메모리로 돌려준다.
    JSON/CSV 중간 결과 파일은 일부러 만들지 않는다.
    """
    ap=argparse.ArgumentParser(description='ACTF Codex V5: Global + FOUR evidenced SQLite DBs + rollout differential recovery')
    ap.add_argument('--codex-home',type=Path,required=True,help='Acquired COPY of .codex directory')
    ap.add_argument('--output-dir',type=Path,default=Path('ACTF_삭제대화_복원결과'))
    ap.add_argument('--logs-dir',type=Path,default=None,help='Optional separately acquired Desktop .log directory')
    ap.add_argument('--thread-id',default=None,help='Analyze only this Thread ID (if discovered or supplied)')
    ap.add_argument('--include-unknown',action='store_true',help='Also recover missing-file cases WITHOUT deletion evidence; separate status')
    ap.add_argument('--fragments',action='store_true',help='Write unverified raw fragment diagnostics separately')
    ap.add_argument('--max-hits',type=int,default=5)
    ap.add_argument('--carve-max-per-page',type=int,default=25)
    ap.add_argument('--max-text-chars',type=int,default=0,help='Display-only truncation; 0=full')
    ap.add_argument('--show-logs',action='store_true',help='Show runtime logs in recovered message report')
    opts=ap.parse_args(argv)
    if opts.max_hits<0 or opts.carve_max_per_page<0 or opts.max_text_chars<0:
        ap.error('Limits cannot be negative')
    if opts.thread_id and not UUID.fullmatch(opts.thread_id):
        ap.error('--thread-id must be exact UUID')
    root=opts.codex_home.expanduser().resolve()
    if not root.is_dir():
        raise ValueError('Acquired .codex evidence directory not found: '+str(root))
    dest=opts.output_dir.expanduser().resolve()
    if write_reports and (dest==root or root in dest.parents):
        raise ValueError('Output MUST be OUTSIDE evidence directory')
    if opts.logs_dir and not opts.logs_dir.is_dir():
        raise ValueError('Optional --logs-dir does not exist')
    marker,projectless=load_global_catalog(root,quiet=True)
    prompt_catalog=load_global_prompt_history(root,quiet=True)
    indexed=load_simple_index(root)
    rollout,inventory_errors=v5_rollout_inventory(root)
    dbpaths=[v5_select_db(root,'state'),v5_select_db(root,'history'),v5_select_db(root,'logs'),v5_select_db(root,'catalog')]
    dbs=[p for p in dbpaths if p.is_file() and page_size(p.read_bytes()[:100])]
    known=set(marker)|set(prompt_catalog)|set(indexed)|set(projectless)
    typed=discover_structured(root,[p for p in dbs if p.name!='codex-dev.db'])
    wal_typed=discover_wal_structured_threads(dbs)
    known|=typed|wal_typed
    sidecar_audit=[inspect_database_sidecars(db) for db in dbs]
    sidecar_by_db={row['db']:row for row in sidecar_audit}
    # UUID 문자열만으로는 스레드로 인정하지 않는다. 넓은 포렌식 탐색에서는
    # state 또는 history를 포함한 *서로 다른 DB 2개 이상*에서 보인 미검증 후보만 남긴다.
    # 더 강한 증거가 나오기 전(또는 사용자가 원인 불명 복원을 요청하기 전)까지는 '원인 불명' 상태다.
    raw_sources=defaultdict(set)
    for path in dbs:
        for tid in discover_raw_uuids(path):
            raw_sources[tid].add(path.name)
    raw_crosssource={tid for tid,srcs in raw_sources.items()
                     if len(srcs)>=2 and any(v5_db_family(name) in ('state','history') for name in srcs)}
    known|=raw_crosssource
    localcatalog,cataloginfo=v5_catalog_refs(v5_select_db(root,'catalog'),known)
    known|=localcatalog
    if opts.thread_id: known={opts.thread_id.lower()}
    if not known:
        raise ValueError('No thread IDs found in acquired Global/SQLite/index. Check evidence completeness.')
    # 일반/보관/없는 파일을 모두 목록화하지만, 삭제 근거를 조사할 만한 '없는' 경우만 복원 보고에 들어간다.
    observations=v5_observations(root,opts.logs_dir,known)
    historic=v5_historical_log_observations(root,known,opts.carve_max_per_page)
    for tid,items in historic.items():observations[tid].extend(items)
    snapshots=v5_state_archive_snapshot(root,known)
    audit=[];targets=[]
    for tid in sorted(known,key=lambda k:(k not in marker,k)):
        files=rollout.get(tid,{'normal':[],'archived':[]})
        state,meaning,selected=v5_assess(tid,files,tid in marker,observations.get(tid,[]),inventory_errors,snapshots.get(tid))
        # 원인 불명 경우는 조사하더라도 '삭제됨'으로 기술하지 않는다.
        if opts.include_unknown and state in ('MISSING_UNKNOWN','ARCHIVE_HISTORY_MISSING'):
            selected=True
        if selected: targets.append(tid)
        audit.append({'thread_id':tid,'classification':state,'description':meaning,'recover':selected,
                      'global_marker':tid in marker,'rollout_files':files,
                      'log_observations':observations.get(tid,[]),
                      'catalog_references':cataloginfo.get(tid,[]),
                      'current_state_snapshot':snapshots.get(tid),
                      'prompt_history_entries':len(prompt_catalog.get(tid,[]))})
    idx=RecoveryIndex(root,{})
    diag=[];stats=[]
    ingest_global_records(root,prompt_catalog,targets,idx)
    selected_set=set(targets)
    for tid in targets:
        if tid in indexed:
            x=indexed[tid];p=root/'session_index.jsonl'
            idx.add(tid,'catalog_metadata',{'title':x.get('title'),'source':'session_index.jsonl'},
                    source_ref(p,root,idx.digest(p),'line='+str(x['source_index_line']),'SESSION_INDEX'),
                    time_entry(x.get('updated_at'),'session_index_updated_at'),
                    source_order=x['source_index_line'],verification='session_index_catalog')
        for info in cataloginfo.get(tid,[]):
            p=Path(info['source'])
            idx.add(tid,'catalog_metadata',{'title':info['title'],'source_kind':info['source_kind']},
                    source_ref(p,root,idx.digest(p),'catalog_by_thread_id','CATALOG_CURRENT'),
                    verification='sqlite_catalog_metadata',
                    dedup_key=('catalog_current',tid,info['source_kind'],info['title']))
    for db in dbs:
        print('[SCAN]',db.relative_to(root),flush=True)
        if not targets:
            stats.append({'db':str(db.relative_to(root)),'records':0,'reason':'no selected absent-rollout threads',
                          'sidecar_audit':sidecar_by_db.get(db.name)})
            continue
        try:
            count=decode_sqlite_evidence(db,selected_set,idx,root,opts.fragments,opts.max_hits,diag,
                                         opts.carve_max_per_page,sidecar_by_db.get(db.name))
            stats.append({'db':str(db.relative_to(root)),**count,
                          'sidecar_audit':sidecar_by_db.get(db.name)})
        except (sqlite3.Error,OSError,ValueError,MemoryError) as exc:
            stats.append({'db':str(db.relative_to(root)),'scan_error':str(exc)})
            print('[WARN]',db.name,str(exc),file=sys.stderr)
    add_first_input_references(idx)
    if opts.logs_dir and targets:
        ingest_optional_text_logs(opts.logs_dir,selected_set,idx,root,max_lines=300)
    grouped=defaultdict(list)
    for e in idx.records: grouped[e['thread_id']].append(e)
    auditmap={x['thread_id']:x for x in audit}
    sessions=[];events=[]
    for tid in targets:
        es=sorted(grouped.get(tid,[]),key=sort_key)
        session=calculate_session(tid,es,marker,indexed,{})
        session['delete_assessment']=auditmap[tid]['classification']
        session['delete_assessment_meaning']=auditmap[tid]['description']
        session['log_observations']=auditmap[tid]['log_observations']
        session['global_prompt_count']=auditmap[tid]['prompt_history_entries']
        session['physical_rollout_absent']=True
        sessions.append(session);events.extend(es)
    manifest=[]
    for file in [root/'.codex-global-state.json',root/'.codex-global-state.json.bak',
                 root/'session_index.jsonl']+dbs:
        if not file.is_file(): continue
        manifest.append({'path':str(file.relative_to(root)),'sha256':idx.digest(file),'bytes':file.stat().st_size})
        if file in dbs:
            for ext in ('-wal','-shm'):
                side=Path(str(file)+ext)
                if side.is_file():
                    manifest.append({'path':str(side.relative_to(root)),
                                     'sha256':idx.digest(side),'bytes':side.stat().st_size})
    # 파일 경로만 기록하는 것은 관측한 내용을 기록하는 것보다 약하다.
    # 일반/보관 세션을 *제외*하는 근거가 된 실제 Rollout 파일의 해시를 남긴다.
    hashed_rollouts=set()
    for groups in rollout.values():
        for paths in groups.values():
            for raw_path in paths:
                file=Path(raw_path)
                if raw_path in hashed_rollouts or not file.is_file():
                    continue
                hashed_rollouts.add(raw_path)
                try:
                    manifest.append({'path':str(file.relative_to(root)),
                                     'sha256':idx.digest(file),'bytes':file.stat().st_size,
                                     'purpose':'actual_existing_rollout_presence'})
                except (OSError,ValueError):
                    pass
    model={'format_version':V5_VERSION,'source_root':str(root),
           'generated_at_utc':datetime.now(timezone.utc).isoformat(),
           'rollout_collection_errors':inventory_errors,
           'discovery':{'global_marker_count':len(marker),'global_prompt_threads':len(prompt_catalog),
                        'typed_sqlite_thread_count':len(typed),'typed_wal_thread_count':len(wal_typed),
                        'catalog_local_discoveries':len(localcatalog),
                        'raw_crosssource_candidates_unverified':len(raw_crosssource),
                        'candidate_threads':len(audit),'selected_for_recovery':len(targets)},
           'audit':audit,'sessions':sessions,'events':events,'sqlite_scan':stats,
           'source_manifest':manifest,'sidecar_audit':sidecar_audit,
           'limitations':['File absence is not proof of deletion or a user-initiated action.',
                'A log event token requires manual transaction/RPC review; this script does not claim cryptographic deletion proof.',
                'Global writing-block deleted marker is deletion-related metadata, not independent thread-delete proof.',
                'Freelist/WAL structured records may be historical, uncommitted, or duplicates; not necessarily deleted dialogue.',
                'SHM is volatile WAL-index metadata only; it contains no chat payload and is not needed for recovery.',
                'WAL overflow uses a reconstructed transaction snapshot plus acquired main-DB; intermediate frames need provenance review and missing historical overflow cannot be recreated.',
                'Global prompt-history inputs are composer history; individual send times and actual submission are unverified.',
                'Only acquired, readable data is analyzed; no disk-image/unallocated-space carving.']}
    if write_reports:
        dest.mkdir(parents=True,exist_ok=True)
        v5_write_summary(dest/'01_삭제여부_교차검증.txt',model)
        v5_write_recovered(dest/'02_복원내용.txt',model,opts.max_text_chars,opts.show_logs)
        if diag and opts.fragments:
            write_diagnostics(dest/'04_검증전_RAW_진단.txt',diag)
        print('[OK] Korean TXT ready:',dest)
        print('[COUNTS] Candidates=',len(audit),'Selected=',len(targets),'Recovered events=',len(events))
        print('[NOTICE] Log token ≠ completed deletion transaction until independently correlated.')
    return model


# V5 삭제 여부 교차검증 요약을 한글 TXT로 쓴다 (판정, 로그 관측, 해시 목록, 분석 한계)
def v5_write_summary(file,model):
    with file.open('w',encoding='utf-8-sig',newline='\n') as f:
        f.write('ACTF Codex 삭제 여부 교차검증 / Global + 4 SQLite + 2 Rollout 폴더\n')
        f.write('분석 대상 루트: '+model['source_root']+'\n')
        f.write('주의: 원본 파일 부재만으로 삭제를 확정하지 않습니다.\n')
        f.write('직접 삭제 완료로 확정하려면 로그 원문에서 실제 이벤트·대상 ID·요청/완료를 검토해야 합니다.\n\n')
        f.write('탐색 통계: '+json.dumps(model['discovery'],ensure_ascii=False)+'\n')
        f.write('\n[SQLite WAL/SHM 교차검증]\n')
        for sc in model.get('sidecar_audit', []):
            f.write(str(sc.get('db'))+' | WAL='+str(sc.get('wal_exists'))+
                    ' | 체크섬 유효 프레임='+str(sc.get('wal_checksum_valid_frames',0))+
                    ' | SHM='+str(sc.get('shm_status'))+
                    ' | SHM↔WAL 페이지 불일치='+str(sc.get('frame_page_mismatches',0))+'\n')
        f.write('주의: SHM에는 대화 본문이 없으며, SHM 불일치는 WAL에서 검증한 원본 프레임을 무효화하지 않습니다.\n')
        for error in model['rollout_collection_errors']: f.write('수집 경고: '+error+'\n')
        f.write('\n'+'='*88+'\n')
        for x in model['audit']:
            f.write('\nThread ID: '+x['thread_id']+'\n')
            f.write('판정: '+x['description']+' ['+x['classification']+']\n')
            f.write('복원 대상: '+('예' if x['recover'] else '아니오')+'\n')
            f.write('Global 삭제 관련 표시: '+('예' if x['global_marker'] else '아니오')+'\n')
            f.write('Global prompt-history 수: '+str(x['prompt_history_entries'])+'\n')
            for tag,paths in x['rollout_files'].items():
                f.write(tag+' Rollout 실제 파일: '+(', '.join(paths) if paths else '없음')+'\n')
            if x.get('current_state_snapshot'):
                f.write('state SQLite 현재 스냅샷: '+json.dumps(x['current_state_snapshot'],ensure_ascii=False)+'\n')
            if x['catalog_references']:
                f.write('SQLite catalog: '+str(len(x['catalog_references']))+' 참고 레코드\n')
            if not x['log_observations']:
                f.write('삭제/보관 로그 토큰: 찾지 못함(로그 미보존 가능)\n')
            for obs in x['log_observations']:
                f.write('  로그: '+obs['type']+' '+obs['source']+' '+obs['record']+' '
                        +compact_date(obs['time'])+'\n')
                f.write('  원문 일부: '+obs['excerpt'].replace('\n',' ')+'\n')
        f.write('\n\n증거 SHA256 목록\n')
        for item in model['source_manifest']:
            f.write(item['path']+'  '+item['sha256']+'  bytes='+str(item['bytes'])+'\n')
        f.write('\n분석 한계\n')
        for x in model['limitations']:f.write('- '+x+'\n')


# V5 복원 내용을 한글 TXT로 쓴다 (세션별, 시각 있는 기록/없는 기록 구분)
def v5_write_recovered(file,model,max_chars,show_logs):
    eventmap={x['event_id']:x for x in model['events']}
    with file.open('w',encoding='utf-8-sig',newline='\n') as f:
        f.write('ACTF Codex V5 / Rollout 없는 스레드의 복원 결과\n')
        f.write('시각: 검증 가능한 기록만 KST, Global 프롬프트는 개별 시간 없음\n')
        f.write('삭제 완료 로그 토큰은 원문 검토 전 최종 입증으로 취급하지 않음\n\n')
        for s in model['sessions']:
            f.write('='*88+'\n')
            f.write('Thread ID: '+s['thread_id']+'\n')
            f.write('삭제 분류: '+s['delete_assessment_meaning']+'\n')
            f.write('제목: '+str(s['title'] or '미확인')+'\n')
            f.write('생성: '+compact_date(s['created_at'])+'\n')
            f.write('복원 완전성: '+s['recovery_status']+'\n')
            f.write('건수: '+json.dumps(s['counts'],ensure_ascii=False)+'\n')
            entries=[eventmap[eid] for eid in s['event_ids_in_report_order']]
            entries=[x for x in entries if show_logs or x['kind'] not in ('runtime_log','desktop_log')]
            if not entries:f.write('현재 획득 가능한 구조화된 복원 내용 없음\n')
            for timed,label in ((True,'검증된 개별 타임스탬프 있음'),(False,'개별 타임스탬프 없음')):
                subset=[e for e in entries if bool(e['timestamp'])==timed]
                if subset:f.write('\n-- '+label+' --\n')
                for e in subset:
                    f.write('\n['+e['kind']+'] '+compact_date(e['timestamp'])+' / '+e['verification']+'\n')
                    f.write('  '+(event_display(e)[:max_chars] if max_chars else event_display(e)).replace('\n','\n  ')+'\n')
                    for ref in e['evidence']:
                        f.write('  출처: '+str(ref['file'])+' / '+str(ref.get('method'))+' / '+str(ref.get('location'))+'\n')
            f.write('\n')


if __name__=='__main__':
    try:
        enable_unicode_output()
        v5_recover()
    except (ValueError,OSError) as exc:
        print('[ERROR]',exc,file=sys.stderr)
        sys.exit(2)
