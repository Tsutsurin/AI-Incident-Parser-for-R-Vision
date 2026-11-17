"""Stateless command-line integration for R-Vision SOAR.

Incident text arrives via stdin or --incident. A successful invocation writes
exactly one JSON object to stdout; errors go to stderr.
"""

import argparse
import json
import logging
import sys
from pathlib import Path
import socket
import urllib.error
from typing import Any, Dict, List, Optional

from app.main import call_llm, load_reference, make_messages, read_json, validate_result

ROOT = Path(__file__).resolve().parent.parent
LOGGER = logging.getLogger("incident_parser.soar")
MAX_INCIDENT_LENGTH = 100_000


def parse_incident(incident: str, config_dir: Path) -> Dict[str, Any]:
    """Process one incident without writing any files."""
    incident = incident.strip()
    if not incident:
        raise ValueError("Incident text is empty")
    if len(incident) > MAX_INCIDENT_LENGTH:
        raise ValueError("Incident text exceeds maximum length")

    settings = read_json(config_dir / "settings.json")
    refs = load_reference(config_dir)
    raw = call_llm(settings, make_messages(incident, refs))
    if not isinstance(raw, dict):
        raise TypeError("LLM result must be a JSON object")
    if raw.get("error"):
        raise ValueError("LLM classification failed: {}".format(raw['error']))
    return validate_result(raw, refs).model_dump()


def main(argv: Optional[List[str]] = None) -> int:
    """Read incident input, emit one JSON result, and return an exit code."""
    argument_parser = argparse.ArgumentParser(
        description="AI Incident Parser for R-Vision SOAR"
    )
    input_group = argument_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--incident", type=str, help="Incident text")
    input_group.add_argument(
        "--stdin", action="store_true", help="Read incident text from stdin"
    )
    argument_parser.add_argument(
        "--config", type=Path, default=ROOT / "config", help="Config directory"
    )
    args = argument_parser.parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        incident = sys.stdin.read(MAX_INCIDENT_LENGTH + 1) if args.stdin else args.incident
        result = parse_incident(incident, args.config)
        print(
            json.dumps(result, ensure_ascii=False, separators=(",", ":")),
            flush=True,
        )
        return 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        urllib.error.URLError,
        socket.timeout,
    ) as exc:
        LOGGER.error("Incident processing failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
