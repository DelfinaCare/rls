from rls.rls_session import RlsSession
from pydantic import BaseModel
from test.engines import sync_engine as engine
from sqlalchemy import text


class MyContext(BaseModel):
    account_id: int
    provider_id: int


context = MyContext(account_id=1, provider_id=2)

session = RlsSession(context=context, bind=engine)


res = session.execute(text("SELECT * FROM items")).fetchall()
print("res:", res)


with session.bypass_rls() as session:
    res2 = session.execute(text("SELECT * FROM items")).fetchall()
    print("res2:", res2)


# TODO: in init must create a bypass_rls_role that is super or has bypass rls privilege amongst with most others
