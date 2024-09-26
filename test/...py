import asyncio
import httpx

async def get_items(user_id):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"http://localhost:8000/users/{user_id}/items")
        print(f"User {user_id}: {response.json()}")

async def main():
    await asyncio.gather(
        get_items(1),
        get_items(2),
    )

asyncio.run(main())
