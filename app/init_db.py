"""Create the tables in the database configured in .env:  python -m app.init_db"""
from .db import Base, engine
from . import models  # noqa: F401  (registers the tables)

if __name__ == "__main__":
    Base.metadata.create_all(engine)
    print("Tables ready:", ", ".join(Base.metadata.tables))
