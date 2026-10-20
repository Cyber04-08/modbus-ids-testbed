"""
Capture the TUNING session - a labeled scenario run kept apart from testing.

The evaluation uses three independent capture sessions:
  * train - testbed/capture_baseline.py -> data/baseline_capture.csv (normal only)
  * tune  - this script                 -> data/tuning_labeled.csv
  * test  - attacks/run_scenario.py + data/label_dataset.py (one per test run)

Any detector setting chosen from labeled data (today: the Isolation Forest's
contamination) is chosen from this session only, so the test sessions' labels
are used for nothing except final scoring.

Usage:
    python attacks/capture_tuning.py

The previous tuning session (and its manifest) is moved to data/backups/
first, never overwritten. The new session is also left in data/labeled.csv;
evaluate.py refuses to use it as the test set (it would be scored against
itself), so capture a fresh test session or pass a saved run.
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
TUNE_CSV = DATA_DIR / "tuning_labeled.csv"
TUNE_MANIFEST = DATA_DIR / "tuning_manifest.json"

sys.path.insert(0, str(ROOT / "testbed"))
from capture_baseline import back_up  # noqa: E402


def main() -> None:
    subprocess.run([sys.executable, str(ROOT / "attacks" / "run_scenario.py")], check=True, cwd=ROOT)
    subprocess.run([sys.executable, str(DATA_DIR / "label_dataset.py")], check=True, cwd=ROOT)
    back_up(TUNE_CSV)
    back_up(TUNE_MANIFEST)
    shutil.copyfile(DATA_DIR / "labeled.csv", TUNE_CSV)
    shutil.copyfile(DATA_DIR / "attack_manifest.json", TUNE_MANIFEST)
    print(f"[tune] tuning session saved -> {TUNE_CSV}")


if __name__ == "__main__":
    main()
