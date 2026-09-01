#!/usr/bin/env python3
"""Minimal mysql stand-in for sshx compiled-binary E2E."""
from __future__ import annotations

import json
import os
import re
import sys

STATE_PATH = os.path.join(os.environ.get("HOME", "."), "mysql-fixture.json")


def load_state():
    if not os.path.exists(STATE_PATH):
        return {"users": [{"id": "1", "name": "old"}]}
    with open(STATE_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh)
    os.replace(tmp, STATE_PATH)


def collect_sql(argv):
    sql = []
    i = 0
    while i < len(argv):
        if argv[i] == "-e" and i + 1 < len(argv):
            sql.append(argv[i + 1])
            i += 2
            continue
        i += 1
    if not sql:
        sql.append(sys.stdin.read())
    return "\n".join(sql)


def skip_names(argv):
    return "-N" in argv or "--skip-column-names" in argv


def emit_rows(columns, rows, no_header):
    if not no_header:
        sys.stdout.write("\t".join(columns) + "\n")
    for row in rows:
        sys.stdout.write("\t".join(row.get(col, "") for col in columns) + "\n")


def match_where(row, where):
    if not where:
        return True
    m = re.search(r"(?i)(\w+)\s*=\s*'([^']*)'", where)
    if m:
        return str(row.get(m.group(1), "")) == m.group(2)
    m = re.search(r"(?i)(\w+)\s*=\s*(\d+)", where)
    if m:
        return str(row.get(m.group(1), "")) == m.group(2)
    return True


def main():
    argv = sys.argv[1:]
    sql = collect_sql(argv)
    no_header = skip_names(argv)
    state = load_state()
    statements = [part.strip() for part in sql.split(";") if part.strip()]
    last_count = 0
    for stmt in statements:
        upper = stmt.upper()
        if upper.startswith("EXPLAIN"):
            sys.stdout.write('{"query_block":{"table":{"table_name":"users","rows":1}}}\n')
            continue
        if "SELECT CASE WHEN" in upper:
            sys.stdout.write("0\n")
            continue
        created = re.match(
            r"(?is)CREATE TABLE\s+(\w+)\s+AS\s+SELECT\s+\*\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?",
            stmt,
        )
        if created:
            dest, src, where = created.group(1), created.group(2), created.group(3)
            rows = [dict(row) for row in state.get(src, []) if match_where(row, where)]
            state[dest] = rows
            save_state(state)
            continue
        updated = re.match(
            r"(?is)UPDATE\s+(\w+)\s+SET\s+(\w+)\s*=\s*'([^']*)'\s+WHERE\s+(.+)",
            stmt,
        )
        if updated:
            table, col, value, where = updated.group(1), updated.group(2), updated.group(3), updated.group(4)
            count = 0
            for row in state.get(table, []):
                if match_where(row, where):
                    row[col] = value
                    count += 1
            last_count = count
            save_state(state)
            continue
        if upper.startswith("SELECT ROW_COUNT()"):
            emit_rows(["ROW_COUNT()"], [{"ROW_COUNT()": str(last_count)}], no_header)
            continue
        selected = re.match(
            r"(?is)SELECT\s+(\*|\w+)\s+FROM\s+(\w+)(?:\s+WHERE\s+(.+))?",
            stmt,
        )
        if selected:
            cols, table, where = selected.group(1), selected.group(2), selected.group(3)
            rows = [row for row in state.get(table, []) if match_where(row, where)]
            if cols == "*":
                columns = list(rows[0].keys()) if rows else ["id", "name"]
            else:
                columns = [cols]
            emit_rows(columns, rows, no_header)
            continue
        if upper.startswith("SET ") or upper.startswith("START ") or upper.startswith("COMMIT"):
            continue
        sys.stderr.write("fake mysql: unsupported statement: %s\n" % stmt)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
