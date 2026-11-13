#!/usr/bin/env python3
"""Archive Immune proposals that can never be verified.

Proposals created before the bypass text was stored (bypass_payload IS NULL) cannot be
retested, so approving them is refused. They only clutter the queue. This marks the
pending ones ARCHIVED; nothing is deleted and no rule changes.

    python scripts/archive_legacy_proposals.py            # report only
    python scripts/archive_legacy_proposals.py --apply
"""
import argparse
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parent.parent / "data" / "immune_system.db"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=str(DB))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    conn = sqlite3.connect(args.db)
    where = "status = 'PENDING' AND (bypass_payload IS NULL OR bypass_payload = '')"
    count = conn.execute(f"SELECT COUNT(*) FROM proposals WHERE {where}").fetchone()[0]
    print(f"{count} pending proposals have no stored bypass text")
    if args.apply and count:
        conn.execute(f"UPDATE proposals SET status = 'ARCHIVED', proposal_state = 'ARCHIVED_NOT_RETESTABLE' WHERE {where}")
        conn.commit()
        print(f"archived {count}")
    print(dict(conn.execute("SELECT status, COUNT(*) FROM proposals GROUP BY status").fetchall()))


if __name__ == "__main__":
    main()
