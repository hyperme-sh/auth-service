"""Install the owner baseline and additive, non-durable SIWE challenge table."""
import argparse
from importlib.resources import files
from pathlib import Path
from sqlalchemy import create_engine, text
from controlplane_events.owner_schema import migrate
from controlplane_events.store import normalize_sync_url


def install(engine):
    migrate(engine, revision='0001_owner_schema', ddl=files('auth_service').joinpath('migrations/0001.sql').read_text())
    with engine.begin() as db:
        db.exec_driver_sql("SELECT pg_advisory_xact_lock(hashtextextended(current_schema(),0))")
        db.exec_driver_sql(files('auth_service').joinpath('migrations/0002_siwe_challenges.sql').read_text())
        persistence = db.execute(text("SELECT relpersistence FROM pg_class WHERE oid=to_regclass('auth_siwe_challenges')")).scalar_one()
        if persistence != 'u':
            raise ValueError('SIWE challenges must use the non-durable owner table')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database-url-file', type=Path, required=True)
    args = parser.parse_args()
    engine = create_engine(normalize_sync_url(args.database_url_file.read_text()))
    try: install(engine)
    finally: engine.dispose()


if __name__ == '__main__': main()
