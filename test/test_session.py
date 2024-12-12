from rls.rls_session import RlsSession
from pydantic import BaseModel
from test.engines import sync_engine as engine
from sqlalchemy import text


class MyContext(BaseModel):
    account_id: int


context = MyContext(account_id=1)

session = RlsSession(context=context, bind=engine)


# res = session.execute(text("SELECT * FROM items")).fetchall()
# print("res:", res)

res_users = session.execute(text("SELECT * FROM users")).fetchall()
print("res_users:", res_users)

# with session.bypass_rls() as session:
#     res2 = session.execute(text("SELECT * FROM items")).fetchall()
#     print("res2:", res2)
