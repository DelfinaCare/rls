from sqlalchemy.orm import sessionmaker
from rls.rls_session import RlsSession
from rls.rls_sessioner import RlsSessioner, ContextGetter
from pydantic import BaseModel
from test.engines import sync_engine as engine
from sqlalchemy import text


# Mock context model
class ExampleContext(BaseModel):
    account_id: int
    provider_id: int


# Concrete implementation of ContextGetter
class ExampleContextGetter(ContextGetter):
    def get_context(self, *args, **kwargs) -> ExampleContext:
        return ExampleContext(account_id=1, provider_id=2)


my_context = ExampleContextGetter()

session_maker = sessionmaker(
    class_=RlsSession, autoflush=False, autocommit=False, bind=engine
)


with RlsSessioner(sessionmaker=session_maker, context_getter=my_context)() as session:
    res = session.execute(text("SELECT * FROM users")).fetchall()
    print(res)
