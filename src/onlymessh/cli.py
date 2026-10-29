"""Command-line entry point."""

from __future__ import annotations

import logging
import signal
import sys
import time

from . import __version__
from .config import from_args
from .sync import sync_once
from .ufw import Ufw, UfwError

log = logging.getLogger("onlymessh")


def _setup_logging(log_file: str | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        handlers=handlers,
    )


def _handle_signal(signum, frame) -> None:
    raise KeyboardInterrupt(f"signal {signum}")


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    cfg = from_args(argv)
    _setup_logging(cfg.log_file)
    log.info(
        "onlymessh %s | domain=%s interval=%ss dry_run=%s",
        __version__, cfg.domain, cfg.interval, cfg.dry_run,
    )

    try:
        ufw = Ufw(cfg.ufw_cmd)
    except UfwError as exc:
        log.error("%s", exc)
        return 2

    signal.signal(signal.SIGTERM, _handle_signal)

    while True:
        try:
            sync_once(cfg, ufw)
        except UfwError as exc:
            log.error("ufw: %s", exc)
        except KeyboardInterrupt:
            log.info("stopping")
            return 0
        except Exception:  # a long-running loop must survive surprises
            log.exception("unexpected error")

        if cfg.once:
            return 0
        try:
            time.sleep(cfg.interval)
        except KeyboardInterrupt:
            log.info("stopping")
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
