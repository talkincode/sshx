#!/usr/bin/env python3
"""Protocol-only mysql stand-in; NOT evidence of real MySQL transaction semantics."""
from __future__ import annotations

import json
import os
import re
import sys

STATE_PATH = os.path.join(os.environ.get("HOME", "."), "mysql-fixture.json")
OPTIONS_PATH = os.path.join(os.environ.get("HOME", "."), "mysql-fixture-options.json")


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save_state(state):
    staging = STATE_PATH + ".staging"
    with open(staging, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(staging, STATE_PATH)


def match_where(row, where):
    if not where:
        return True
    match = re.search(r"(?i)(\w+)\s*=\s*(?:'([^']*)'|(\d+))", where)
    return match is None or str(row.get(match.group(1), "")) == (match.group(2) or match.group(3))


def statements(argv):
    if "-e" in argv:
        yield argv[argv.index("-e") + 1]
        return
    pending = ""
    # Streaming is essential: sshx deliberately withholds mutation SQL until
    # it has consumed and persisted this client's complete preimage output.
    for line in sys.stdin:
        pending += line
        if pending.rstrip().endswith(";"):
            yield pending.strip().rstrip(";")
            pending = ""


def main():
    state = load_json(STATE_PATH, {"users": [{"id": "1", "name": "old"}]})
    options = load_json(OPTIONS_PATH, {})
    last_count = 0
    transactional = False
    snapshot_table, snapshot_where = "users", ""
    for stmt in statements(sys.argv[1:]):
        upper = stmt.upper()
        marker = re.fullmatch(r"SELECT '(__SSHX_SQL_V1_[^']+)'", stmt)
        if marker:
            frame = marker.group(1)
            if not (options.get("omit_commit_ack") and "|commit|" in frame):
                print(frame, flush=True)
            continue
        count = re.fullmatch(r"SELECT CONCAT\('(__SSHX_SQL_V1_[^']+affected\|)', ROW_COUNT\(\)\)", stmt)
        if count:
            print(count.group(1) + ("bad" if options.get("bad_count") else str(last_count)), flush=True)
            continue
        if upper.startswith("EXPLAIN"):
            table_plan = {"table_name": "users", "access_type": "ALL"}
            if "INSERT" in upper:
                table_plan["insert"] = True
            elif not options.get("omit_row_estimate"):
                table_plan["rows"] = 1
            plan = json.dumps({"query_block": {"table": table_plan}}, indent=2)
            if "--raw" not in sys.argv:
                plan = plan.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")
            print(plan, flush=True)
            continue
        if upper.startswith("SELECT CASE WHEN"):
            print("0", flush=True)
            continue
        if upper.startswith("SET AUTOCOMMIT=0"):
            transactional = True
            continue
        if upper.startswith("SET @SSHX_SNAPSHOT_SQL"):
            source = re.search(r"FROM (\w+)'", stmt)
            encoded = re.search(r"CONVERT\(0x([0-9a-f]+)", stmt)
            snapshot_table = source.group(1) if source else "users"
            snapshot_where = bytes.fromhex(encoded.group(1)).decode() if encoded else ""
            continue
        if upper.startswith("SELECT 'SSHX_MYSQL_HEX_ROWS_V1'"):
            print("SSHX_MYSQL_HEX_ROWS_V1", flush=True)
            continue
        if upper.startswith("SELECT CONCAT('C|'"):
            print("C|1|6964|696e74\nC|2|6e616d65|74657874", flush=True)
            continue
        if upper == "EXECUTE SSHX_SNAPSHOT":
            for row in state.get(snapshot_table, []):
                if match_where(row, snapshot_where):
                    fields = ["N" if row.get(col) is None else "H" + str(row[col]).encode().hex() for col in ("id", "name")]
                    print("R|" + "|".join(fields), flush=True)
            continue
        if upper == "EXECUTE SSHX_GUARD":
            if options.get("unsupported_engine"):
                print("fake mysql: unsupported table engine", file=sys.stderr)
                return 2
            continue
        inserted = re.match(r"(?is)INSERT\s+INTO\s+(\w+)\s*(?:\(\s*id\s*,\s*name\s*\))?\s*VALUES\s*\(\s*(\d+)\s*,\s*'([^']*)'\s*\)", stmt)
        if inserted:
            table, identifier, value = inserted.groups()
            state.setdefault(table, []).append({"id": identifier, "name": value})
            last_count = 1
            if not transactional:
                save_state(state)
            continue
        updated = re.match(r"(?is)UPDATE\s+(\w+)\s+SET\s+(\w+)\s*=\s*'([^']*)'\s+WHERE\s+(.+)", stmt)
        if updated:
            if options.get("fail_mutation"):
                print("fake mysql: rejected mutation private-row-value", file=sys.stderr)
                return 2
            table, col, value, where = updated.groups()
            last_count = 0
            for row in state.get(table, []):
                if match_where(row, where) and row.get(col) != value:
                    row[col] = value
                    last_count += 1
            if not transactional:
                save_state(state)
            continue
        selected = re.match(r"(?is)SELECT\s+(\*|\w+)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?", stmt)
        if selected:
            cols, table, where = selected.groups()
            for row in state.get(table, []):
                if match_where(row, where):
                    names = list(row) if cols == "*" else [cols]
                    print("\t".join(str(row.get(col, "")) for col in names), flush=True)
            continue
        if upper == "COMMIT":
            if transactional:
                save_state(state)
            continue
        if upper.startswith(("SET ", "START ", "LOCK ", "UNLOCK ", "PREPARE ", "DEALLOCATE ", "SELECT GROUP_CONCAT")):
            continue
        print("fake mysql: unsupported protocol statement", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
