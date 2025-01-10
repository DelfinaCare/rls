from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine

ASYNC_DATABASE_URL = "postgresql+asyncpg://my_user:secure_password@localhost/session"
SYNC_DATABASE_URL = "postgresql://my_user:secure_password@localhost/session"
ADMIN_DATABASE_URL = "postgresql://user:password@localhost/session"
async_engine = create_async_engine(ASYNC_DATABASE_URL)
sync_engine = create_engine(SYNC_DATABASE_URL)
admin_engine = create_engine(ADMIN_DATABASE_URL)
setup_engine = create_engine(ADMIN_DATABASE_URL)
