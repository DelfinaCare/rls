import contextlib

import fastapi
import sqlalchemy as sa
import starlette.requests
from sqlalchemy.ext import asyncio as sa_asyncio

from rls import rls_session
from rls import rls_sessioner
from test import database
from test import models


class SampleContextGetter(rls_sessioner.ContextGetter):
    """This is needed to generate the RLS context for each request."""

    def get_context(
        self, request: starlette.requests.Request
    ) -> models.SampleRlsContext:
        account_id_param = request.query_params.get("account_id")
        return models.SampleRlsContext(
            account_id=int(account_id_param) if account_id_param is not None else None
        )


# We then create a sessioner as a fastapi dependency to do the injection.
session_maker = sa.orm.sessionmaker(
    class_=rls_session.RlsSession, autoflush=False, autocommit=False
)
demo_sessioner = fastapi.Depends(
    rls_sessioner.fastapi_dependency_function(
        rls_sessioner.RlsSessioner(
            sessionmaker=session_maker, context_getter=SampleContextGetter()
        )
    )
)

# Async variant using AsyncRlsSession.
async_session_maker = sa_asyncio.async_sessionmaker(
    class_=rls_session.AsyncRlsSession, autoflush=False, autocommit=False
)
async_demo_sessioner = fastapi.Depends(
    rls_sessioner.async_fastapi_dependency_function(
        rls_sessioner.AsyncRlsSessioner(
            sessionmaker=async_session_maker, context_getter=SampleContextGetter()
        )
    )
)


@contextlib.asynccontextmanager
async def sample_database_setup(app: fastapi.FastAPI):
    test_db = database.test_postgres_instance()
    sync_engine = sa.create_engine(test_db.url)
    async_engine = sa_asyncio.create_async_engine(test_db.url)
    session_maker.configure(bind=sync_engine)
    async_session_maker.configure(bind=async_engine)
    yield
    sync_engine.dispose()
    await async_engine.dispose()
    test_db.close()


app = fastapi.FastAPI(lifespan=sample_database_setup)


@app.get("/users")
def get_users(db=demo_sessioner, account_id: int | None = None) -> list[str]:
    del account_id
    # This query will already have the rls context set from the request.
    result = db.execute(sa.select(models.User.username)).scalars()
    data = list(result)
    db.close()
    return data


@app.get("/all_users")
def get_all_users(
    db: rls_session.RlsSession = demo_sessioner, account_id: int | None = None
) -> list[str]:
    del account_id
    with db.bypass_rls():
        result = list(db.execute(sa.select(models.User.username)).scalars())
    data = list(result)
    db.close()
    return data


@app.get("/async/users")
async def async_get_users(
    db: rls_session.AsyncRlsSession = async_demo_sessioner,
    account_id: int | None = None,
) -> list[str]:
    del account_id
    # This query will already have the rls context set from the request.
    result = (await db.execute(sa.select(models.User.username))).scalars()
    return list(result)


@app.get("/async/all_users")
async def async_get_all_users(
    db: rls_session.AsyncRlsSession = async_demo_sessioner,
    account_id: int | None = None,
) -> list[str]:
    del account_id
    async with db.bypass_rls():
        result = list((await db.execute(sa.select(models.User.username))).scalars())
    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "fastapi_sample:app",
        host="0.0.0.0",
        proxy_headers=True,
        reload=True,
        log_level="debug",
    )
