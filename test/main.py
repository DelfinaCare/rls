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


# @app.get("/users/items/1")
# async def get_items_1(db: AsyncSession = Session):
#     stmt = select(Item)
#     result = await db.execute(stmt)
#     items = result.scalars().all()

#     return items


# @app.get("/users/items/2")
# async def get_items_2(db: AsyncSession = Session):
#     stmt = select(Item1)
#     result = db.execute(stmt)
#     items = result.scalars().all()

#     print("**************************************")
#     print(items)
#     print("**************************************")


#     return items


# @app.get("/users/items/3")
# async def get_items_3(db: AsyncSession = Session):
#     stmt = select(Item2)
#     result = db.execute(stmt)
#     items = result.scalars().all()

#     return items


# @app.get("/admin/items")
# async def get_items(db: AsyncSession = Session):
#     stmt = select(Item)
#     results = bypass_rls_async(db, [stmt])
#     items = results[0].scalars().all()
#     return items
