import os
import time
import logging

from sqlalchemy import create_engine, text


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("wait_for_db")


def main() -> None:
    database_url = os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@db:5432/app_db")
    retries = 60
    delay_seconds = 2
    for attempt in range(1, retries + 1):
        try:
            engine = create_engine(database_url, pool_pre_ping=True)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("PostgreSQL is ready")
            return
        except Exception as exc:
            logger.warning("Database not ready (attempt %s/%s): %s", attempt, retries, exc)
            time.sleep(delay_seconds)
    raise RuntimeError("PostgreSQL is not reachable after retries")


if __name__ == "__main__":
    main()
