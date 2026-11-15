import os

from alembic import context
from sqlalchemy import create_engine, pool

from persistguard.models import Base


if context.is_offline_mode():
    context.configure(dialect_name="postgresql")
    with context.begin_transaction():
        context.run_migrations()
else:
    database_url = os.environ.get("PERSISTGUARD_DATABASE_URL")
    if not database_url:
        raise RuntimeError("Set PERSISTGUARD_DATABASE_URL before running migrations.")

    engine = create_engine(database_url, poolclass=pool.NullPool)
    try:
        with engine.connect() as connection:
            context.configure(connection=connection, target_metadata=Base.metadata, compare_server_default=True)
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()
