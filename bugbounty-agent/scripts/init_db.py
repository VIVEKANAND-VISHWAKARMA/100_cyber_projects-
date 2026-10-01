#!/usr/bin/env python3
"""
Initializes the SQLite database with the full schema.
Safe to re-run — uses CREATE TABLE IF NOT EXISTS.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import memory


def main():
    memory.init_db()
    print(f"[+] Database initialized at {memory.DB_PATH}")


if __name__ == "__main__":
    main()
