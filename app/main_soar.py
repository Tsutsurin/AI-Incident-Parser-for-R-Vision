"""Stateless command-line integration for R-Vision SOAR.

Incident text arrives via stdin or --incident. A successful invocation writes
exactly one JSON object to stdout; errors go to stderr.
"""

import argparse
import json
import logging
import signal
import sys
from pathlib import Path
import socket
import urllib.error
from typing import Any, Dict, List, Optional

from app.main import call_llm, make_messages, read_json, validate_result
from app.parser import parse
import time

ROOT = Path(__file__).resolve().parent.parent
LOGGER = logging.getLogger("incident_parser.soar")
MAX_INCIDENT_LENGTH = 100_000


class VerificationDeadline(Exception):
    pass


def _deadline_expired(signum, frame):
    raise VerificationDeadline("LLM verification deadline exceeded")


def parse_incident(incident: str, config_dir: Path) -> Dict[str, Any]:
    """Process one incident without writing any files."""
    incident = incident.strip()
    if not incident:
        raise ValueError("Incident text is empty")
    if len(incident) > MAX_INCIDENT_LENGTH:
        raise ValueError("Incident text exceeds maximum length")

    started = time.monotonic()
    settings = read_json(config_dir / "settings.json")
    result, refs = parse(incident, config_dir)
    verification = settings.get("llm_verification", {})
    if verification.get("enabled", False):
        try:
            budget = min(5.0, float(verification.get("timeout", 3)))
            if budget <= 0:
                raise ValueError("Invalid verification timeout")
            options = dict(settings, timeout=budget, max_duration=budget,
                           max_retries=0, num_predict=256)
            previous_handler = signal.getsignal(signal.SIGALRM)
            signal.signal(signal.SIGALRM, _deadline_expired)
            try:
                signal.setitimer(signal.ITIMER_REAL, budget)
                raw = call_llm(options, make_messages(incident, refs))
                checked = validate_result(raw, refs).model_dump()
                # Verification is advisory: never replace deterministic facts.
                LOGGER.info("LLM verification agreement: %s", checked == result)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous_handler)
        except Exception as exc:
            LOGGER.warning("LLM verification skipped: %s", type(exc).__name__)
    LOGGER.info("Processing time: %.3fs", time.monotonic() - started)
    return result



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
        TimeoutError,
    ) as exc:
        LOGGER.error("Incident processing failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
