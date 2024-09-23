from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, AsyncEngine
from sqlalchemy import text,Result
from sqlalchemy.sql import Executable
from sqlalchemy.sql.elements import TextClause
from sqlalchemy.engine import Engine

import once
import logging
import base64
import json
from typing import Optional, List, Union

from fastapi import Request

from rls.schemas import Policy, ComparatorSource

# --------------------------------------Set RLS variables-----------------------------#


def _base64url_decode(input_str):
    """Decodes a Base64 URL-encoded string."""
    padding = "=" * (4 - (len(input_str) % 4))  # Add necessary padding
    return base64.urlsafe_b64decode(input_str + padding)


def _decode_jwt(token):
    """Decode the JWT without verifying the signature."""
    try:
        # Split the token into header, payload, and signature
        header_b64, payload_b64, signature_b64 = token.split(".")

        # Decode the payload (base64url format)
        decoded_payload = _base64url_decode(payload_b64)

        # Convert the payload from bytes to JSON
        payload = json.loads(decoded_payload)

        return payload
    except (ValueError, json.JSONDecodeError) as e:
        logging.error("Invalid token or payload:", e)
        return None


def _parse_bearer_token(AuthorizationHeader: str):
    """Parse the Bearer token from the Authorization header with safety."""
    if not AuthorizationHeader:
        logging.warning("No Authorization header")
        return None

    parts = AuthorizationHeader.split()
    if parts[0].lower() != "bearer":
        logging.warning("Authorization header does not contain Bearer token")
        return None

    if len(parts) == 1:
        logging.warning("No Bearer token found")
        return None

    if len(parts) > 2:
        logging.warning("Authorization header contains multiple Bearer tokens")
        return None

    return _decode_jwt(parts[1])


def _get_nested_value(dictionary: dict, keys: list[str]):
    """Retrieve the nested value in a dictionary based on a list of keys."""
    value = dictionary
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key, None)
        else:
            return None  # If value is not a dict, return None
        if value is None:
            return None  # Return None if any key is not found
    return value


def _get_set_statements(req: Request) -> Optional[TextClause]:
    # must be setup for the rls_policies key to be set
    queries = []

    RlsBase.metadata.info.setdefault("rls_policies", dict())
    for mapper in RlsBase.registry.mappers:
        if not hasattr(mapper.class_, "__rls_policies__"):
            continue

        table_name = mapper.tables[0].fullname
        policies: list[Policy] = mapper.class_.__rls_policies__

        for policy in policies:
            db_var_name = policy.get_db_var_name(table_name)

            comparator_name = policy.condition_args["comparator_name"]
            comparator_name_split = comparator_name.split(".")

            comparator_value = None
            if (
                policy.condition_args["comparator_source"]
                == ComparatorSource.bearerTokenPayload
            ):
                comparator_value = _get_nested_value(
                    _parse_bearer_token(req.headers.get("Authorization")),
                    comparator_name_split,
                )
            elif (
                policy.condition_args["comparator_source"]
                == ComparatorSource.requestUser
            ):
                comparator_value = _get_nested_value(req.user, comparator_name_split)
            elif policy.condition_args["comparator_source"] == ComparatorSource.header:
                comparator_value = _get_nested_value(req.headers, comparator_name_split)
            else:
                raise ValueError("Invalid Comparator Source")

            if comparator_value is None:
                continue

            temp_query = f"SET LOCAL {db_var_name} = {comparator_value};"

            queries.append(temp_query)

    if len(queries) == 0:
        return None
    combined_query = text("\n".join(queries))  # Combine queries into a single string

    return combined_query


# --------------------------------------RlsBase Initialization-----------------------------#


# RlsBase class for our models
RlsBase = declarative_base()


# --------------------------------------Engines Initialization-----------------------------#


# SQLAlchemy session
AsyncSessionLocal = async_sessionmaker(
    class_=AsyncSession,  # Async session class
    expire_on_commit=False,
)


SyncSessionLocal = sessionmaker(
    class_=Session,
    expire_on_commit=False,
)


# --------------------------------------Deps injection functions-----------------------------#


@once.once
def bind_engine(db_engine: Engine):
    if isinstance(db_engine, AsyncEngine):
        print("Config Async Session")
        AsyncSessionLocal.configure(bind=db_engine)
    elif isinstance(db_engine, Engine):
        print("Config Sync Session")
        SyncSessionLocal.configure(bind=db_engine)
    else:
        raise ValueError("Invalid Engine type")


def get_session(db_engine: Engine):
    bind_engine(db_engine)

    if isinstance(db_engine, AsyncEngine):
        return get_async_session
    elif isinstance(db_engine, Engine):
        return get_sync_session
    else:
        raise ValueError("Invalid Engine type")


def get_sync_session(request: Request):
    with SyncSessionLocal() as session:
        stmts = _get_set_statements(request)
        if stmts is not None:
            session.execute(stmts)
        yield session


# Dependency to get DB session in routes
async def get_async_session(request: Request):
    async with AsyncSessionLocal() as session:
        stmts = _get_set_statements(request)
        if stmts is not None:
            await session.execute(stmts)
        yield session


async def bypass_rls_async(session:AsyncSession,stmts:List[Executable])->List[Result]:
    results=[]
    await session.execute(text("SET row_security=off;"))
    for stmt in stmts:
        results.append(await session.execute(stmt))
    await session.execute(text("SET row_security=on;"))
    return results
        
        
def bypass_rls_sync(session:Session,stmts:List[Executable])->List[Result]:
    results=[]
    session.execute(text("SET row_security=off;"))
    for stmt in stmts:
        results.append(session.execute(stmt))
    session.execute(text("SET row_security=on;"))
    return results