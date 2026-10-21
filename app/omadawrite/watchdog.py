from __future__ import annotations

import logging
import time

from . import db, engine
from .config import Config


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    log = logging.getLogger("omadawrite.watchdog")
    cfg = Config.from_env()
    db.init(cfg.db_path)
    log.info("watchdog up: %ds stable before writing, settle %ds, watch %d min, close after %d min stable, "
             "revert after %d min down, probes %s every %ds",
             cfg.preflight_stable_seconds, cfg.settle_seconds, cfg.watch_minutes, cfg.stable_minutes,
             cfg.revert_after_down_minutes, ",".join(cfg.probe_targets), cfg.tick_seconds)
    while True:
        conn = db.connect(cfg.db_path)
        try:
            engine.tick(cfg, conn)
        except Exception:
            log.exception("tick failed")
        finally:
            conn.close()
        time.sleep(cfg.tick_seconds)


if __name__ == "__main__":
    main()
