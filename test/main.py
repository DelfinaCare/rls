from fastapi import FastAPI, Depends
from rls.rls_sessioner import RlsSessioner
from test.test_sessioner import my_context, session_maker
from sqlalchemy import text
from rls.rls_sessioner import fastapi_dependency_function


app = FastAPI()

rls_sessioner = RlsSessioner(sessionmaker=session_maker, context_getter=my_context)

my_session = Depends(fastapi_dependency_function(rls_sessioner))


@app.get("/users")
async def get_users(db=my_session):
    result = db.execute(text("SELECT * FROM users")).all()
    return dict(result)
