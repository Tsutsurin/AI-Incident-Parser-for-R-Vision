"""Windows EXE entry point for AI Incident Parser."""

import sys
from pathlib import Path

from app import main as parser


def get_app_root() -> Path:
    """Determine the directory containing application files."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    return Path(__file__).resolve().parent.parent


def main() -> int:
    """Run the incident parser with correct application paths."""
    parser.ROOT = get_app_root()
    return parser.main()


if __name__ == "__main__":
    sys.exit(main())
