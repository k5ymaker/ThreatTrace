#!/usr/bin/env python3
"""
scripts/ingest_privesc_samples.py — Ingest EVTX privilege escalation samples
Downloads EVTX-ATTACK-SAMPLES repo (sparse) and copies/parses the
Privilege Escalation folder into data/evtx_samples/privilege_escalation/
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_URL = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git"
REPO_DIR = Path("data/evtx_repo")
SAMPLES_DIR = Path("data/evtx_samples/privilege_escalation")
PRIVESC_PATH = "Privilege Escalation"


def clone_repo(verbose: bool = False) -> None:
    """Sparse-clone only the Privilege Escalation folder."""
    if REPO_DIR.exists():
        print(f"[INFO] Repo already cloned at {REPO_DIR}. Pulling latest...")
        subprocess.run(["git", "-C", str(REPO_DIR), "pull"], check=True,
                       capture_output=not verbose)
        return

    print(f"[INFO] Cloning {REPO_URL} (sparse)...")
    subprocess.run([
        "git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
        REPO_URL, str(REPO_DIR)
    ], check=True, capture_output=not verbose)

    subprocess.run([
        "git", "-C", str(REPO_DIR), "sparse-checkout", "set", PRIVESC_PATH
    ], check=True, capture_output=not verbose)
    print(f"[OK]  Cloned to {REPO_DIR}")


def copy_samples() -> int:
    """Copy EVTX files from repo to samples dir. Returns count of files copied."""
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    src = REPO_DIR / PRIVESC_PATH
    if not src.exists():
        print(f"[ERROR] Source path not found: {src}", file=sys.stderr)
        return 0

    count = 0
    for evtx in src.glob("**/*.evtx"):
        dest = SAMPLES_DIR / evtx.name
        shutil.copy2(evtx, dest)
        count += 1
        print(f"  copied: {evtx.name}")
    print(f"[OK]  {count} EVTX files copied to {SAMPLES_DIR}")
    return count


def parse_samples(verbose: bool = False) -> None:
    """Parse all EVTX files and print record counts."""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    try:
        from parsers.windows_evtx_parser import EVTXParser
    except ImportError as e:
        print(f"[ERROR] Cannot import EVTXParser: {e}", file=sys.stderr)
        return

    parser = EVTXParser()
    total_records = 0
    files = sorted(SAMPLES_DIR.glob("*.evtx"))
    if not files:
        print(f"[WARN] No .evtx files found in {SAMPLES_DIR}")
        return

    print(f"\n{'File':<70} {'Records':>8}")
    print("-" * 80)
    for f in files:
        records = parser.parse_file(str(f))
        total_records += len(records)
        if verbose:
            eids = {}
            for r in records:
                eids[r.event_id] = eids.get(r.event_id, 0) + 1
            eid_str = ", ".join(f"EID {k}:{v}" for k, v in sorted(eids.items()))
            print(f"  {f.name:<68} {len(records):>8}  [{eid_str}]")
        else:
            print(f"  {f.name:<68} {len(records):>8}")
    print("-" * 80)
    print(f"  {'TOTAL':<68} {total_records:>8}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Ingest EVTX privilege escalation samples")
    ap.add_argument("--clone", action="store_true", help="Clone/update the sample repo")
    ap.add_argument("--parse-only", action="store_true",
                    help="Only parse existing samples (skip clone/copy)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    if args.parse_only:
        parse_samples(verbose=args.verbose)
    else:
        clone_repo(verbose=args.verbose)
        copy_samples()
        parse_samples(verbose=args.verbose)
