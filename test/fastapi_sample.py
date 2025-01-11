import contextlib

import fastapi
import sqlalchemy as sa
import starlette.requests

from rls import rls_session, rls_sessioner
from test import database, models


class SampleContextGetter(rls_sessioner.ContextGetter):
    """This is needed to generate the RLS context for each request."""

    def get_context(self, *args, **kwargs) -> models.SampleRlsContext:
        request: starlette.requests.Request = kwargs.get("request")
        return models.SampleRlsContext(
            account_id=request.query_params.get("account_id")
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


@contextlib.asynccontextmanager
async def sample_database_setup(app: fastapi.FastAPI):
    test_db = database.test_postgres_instance()
    session_maker.configure(bind=test_db.non_superadmin_engine)
    yield


app = fastapi.FastAPI(lifespan=sample_database_setup)


@app.get("/users")
def get_users(db=demo_sessioner, account_id: int | None = None) -> list[str]:
    del account_id
    # This query will already have the rls context set from the request.
    result = db.execute(sa.select(models.User.username)).scalars()
    return list(result)


@app.get("/all_users")
def get_all_users(
    db: rls_session.RlsSession = demo_sessioner, account_id: int | None = None
) -> list[str]:
    del account_id
    with db.bypass_rls():
        result = list(db.execute(sa.select(models.User.username)).scalars())
    return list(result)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "fastapi_sample:app",
        host="0.0.0.0",
        proxy_headers=True,
        reload=True,
        log_level="debug",
    )
