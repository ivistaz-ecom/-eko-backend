"""Create the tables in the database configured in .env:  python -m app.init_db"""
from sqlalchemy import inspect, text

from .db import Base, engine
from . import models  # noqa: F401  (registers the tables)

# Columns added after the first install. create_all does not alter existing tables.
_ADDED = {
    "users": {
        "job_function": "VARCHAR(160) NULL",
        "work_location": "VARCHAR(160) NULL",
    },
}


def ensure_columns() -> None:
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, columns in _ADDED.items():
            if table not in insp.get_table_names():
                continue
            have = {col["name"] for col in insp.get_columns(table)}
            for name, ddl in columns.items():
                if name not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


if __name__ == "__main__":
    Base.metadata.create_all(engine)
    ensure_columns()
    print("Tables ready:", ", ".join(Base.metadata.tables))
