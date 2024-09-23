from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select


from rls.database import get_session, bypass_rls_async
from .models import Item

from .engines import async_engine as db_engine


app = FastAPI()

Session = Depends(get_session(db_engine))


@app.get("/users/items")
async def get_users(db: AsyncSession = Session):
    stmt = select(Item)
    result = await db.execute(stmt)
    items = result.scalars().all()

    return items


@app.get("/admin/items")
async def get_items(db: AsyncSession = Session):
    stmt = select(Item)
    results = await bypass_rls_async(db, [stmt])
    items = results[0].scalars().all()
    return items
