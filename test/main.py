from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select


from rls.database import get_session, bypass_rls_async
from .models import Item, Item1, Item2

from .engines import async_engine as db_engine


app = FastAPI()

Session = Depends(get_session(db_engine))


@app.get("/users/items/1")
async def get_items_1(db: AsyncSession = Session):
    stmt = select(Item)
    result = await db.execute(stmt)
    items = result.scalars().all()

    return items


@app.get("/users/items/2")
async def get_items_2(db: AsyncSession = Session):
    stmt = select(Item1)
    result = await db.execute(stmt)
    items = result.scalars().all()

    return items


@app.get("/users/items/3")
async def get_items_3(db: AsyncSession = Session):
    stmt = select(Item2)
    result = await db.execute(stmt)
    items = result.scalars().all()

    return items


@app.get("/admin/items")
async def get_items(db: AsyncSession = Session):
    stmt = select(Item)
    results = await bypass_rls_async(db, [stmt])
    items = results[0].scalars().all()
    return items
