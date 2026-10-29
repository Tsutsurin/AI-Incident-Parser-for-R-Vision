
"""Entry point for the Windows EXE build of AI Incident Parser."""

import logging
import sys
from pathlib import Path

from app import main as parser


def get_app_root() -> Path:
    """Return the executable directory or the project root."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    return Path(__file__).resolve().parent.parent


def main() -> int:
    """Run the existing parser with paths relative to the EXE."""
    parser.ROOT = get_app_root()

    try:
        return parser.main()
    except Exception:
        logging.getLogger("incident_parser").exception(
            "Unexpected application error"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
