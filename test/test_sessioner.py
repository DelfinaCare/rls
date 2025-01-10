from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from rls.rls_session import RlsSession
from rls.rls_sessioner import ContextGetter, RlsSessioner
from test.engines import sync_engine as engine


class ExampleContext(BaseModel):
    account_id: int
    provider_id: int


# Concrete implementation of ContextGetter
class ExampleContextGetter(ContextGetter):
    def get_context(self, *args, **kwargs) -> ExampleContext:
        account_id = kwargs.get("account_id", 1)
        provider_id = kwargs.get("provider_id", 2)
        return ExampleContext(account_id=account_id, provider_id=provider_id)


my_context = ExampleContextGetter()

session_maker = sessionmaker(
    class_=RlsSession, autoflush=False, autocommit=False, bind=engine
)

my_sessioner = RlsSessioner(sessionmaker=session_maker, context_getter=my_context)


with my_sessioner(account_id=22, provider_id=99) as session:
    res = session.execute(text("SELECT * FROM users")).fetchall()
    print(res)  # output: List of users with account_id = 22 and provider_id = 99


with my_sessioner(account_id=11, provider_id=44) as session:
    res = session.execute(text("SELECT * FROM users")).fetchall()
    print(res)  # output: List of users with account_id = 11 and provider_id = 44
