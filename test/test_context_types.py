"""End-to-end tests that every supported context field type is cast by the
policy to the PostgreSQL type of the column it is compared with.

Each case creates a table with a ``value`` column and a policy comparing it to
one context field, then checks which rows an ``RlsSession`` can see.  Cases use
``<=`` where a text comparison would give a different answer than a typed one
(e.g. ``'9' <= '10'`` is false), so they fail if a value is not cast.
"""

import dataclasses
import datetime
import decimal
import enum
import operator
import typing
import unittest
import uuid

import pydantic
import sqlalchemy
import testing.postgresql
from sqlalchemy import orm
from sqlalchemy import sql

from rls import create_policies
from rls import policy
from rls import register
from rls import session

# A non-UTC session time zone, so that time zone handling bugs are not hidden.
_SESSION_TIME_ZONE = "America/New_York"
# Non-superuser role (and password) used to query, since superusers bypass RLS.
_ROLE = "types_user"
_PLUS_5 = datetime.timezone(datetime.timedelta(hours=5))
_UID_A = uuid.UUID("12345678-1234-5678-1234-567812345678")
_UID_B = uuid.UUID("87654321-4321-8765-4321-876543210987")


class Color(enum.Enum):
    # Names differ from values: contexts send enums by value.
    red = "RED"
    blue = "BLUE"


class Level(enum.IntEnum):
    low = 1
    high = 3


class TypesContext(pydantic.BaseModel):
    int_value: int | None = None
    float_value: float | None = None
    decimal_value: decimal.Decimal | None = None
    str_value: str | None = None
    bool_value: bool | None = None
    uuid_value: uuid.UUID | None = None
    date_value: datetime.date | None = None
    time_value: datetime.time | None = None
    timetz_value: datetime.time | None = None
    timestamp_value: datetime.datetime | None = None
    timestamptz_value: datetime.datetime | None = None
    aware_timestamp_value: datetime.datetime | None = None
    enum_value: Color | None = None
    int_enum_value: Level | None = None


@dataclasses.dataclass(frozen=True)
class Case:
    field: str
    column_type: sqlalchemy.types.TypeEngine
    # The type the policy casts the context value to (ConditionArg.type).
    arg_type: type[sqlalchemy.types.TypeEngine] | sqlalchemy.types.TypeEngine
    compare: typing.Callable[[typing.Any, typing.Any], typing.Any]
    rows: list[typing.Any]
    context_value: typing.Any
    # Indexes into ``rows`` of the rows the policy lets through.
    visible: list[int]


_COLOR_ENUM = sqlalchemy.Enum(
    Color, name="color", values_callable=lambda e: [m.value for m in e]
)

CASES = [
    Case(
        "int_value",
        sqlalchemy.Integer(),
        sqlalchemy.Integer,
        operator.le,
        [9, 10, 11],
        10,
        [0, 1],
    ),
    Case(
        "float_value",
        sqlalchemy.Float(),
        sqlalchemy.Float,
        operator.le,
        [9.5, 1e-05, 10.5],
        10.0,
        [0, 1],
    ),
    Case(
        "decimal_value",
        sqlalchemy.Numeric(),
        sqlalchemy.Numeric,
        operator.le,
        [decimal.Decimal("9.5"), decimal.Decimal(100), decimal.Decimal("100.5")],
        decimal.Decimal("1E+2"),
        [0, 1],
    ),
    Case(
        "str_value",
        sqlalchemy.String(),
        sqlalchemy.String,
        operator.eq,
        ["a", "b"],
        "b",
        [1],
    ),
    Case(
        "bool_value",
        sqlalchemy.Boolean(),
        sqlalchemy.Boolean,
        operator.eq,
        [True, False],
        False,
        [1],
    ),
    Case(
        "uuid_value",
        sqlalchemy.Uuid(),
        sqlalchemy.Uuid,
        operator.eq,
        [_UID_A, _UID_B],
        _UID_B,
        [1],
    ),
    Case(
        "date_value",
        sqlalchemy.Date(),
        sqlalchemy.Date,
        operator.le,
        [
            datetime.date(2024, 1, 9),
            datetime.date(2024, 1, 10),
            datetime.date(2024, 1, 11),
        ],
        datetime.date(2024, 1, 10),
        [0, 1],
    ),
    Case(
        "time_value",
        sqlalchemy.Time(),
        sqlalchemy.Time,
        operator.le,
        [
            datetime.time(9, 30),
            datetime.time(10, 0),
            datetime.time(10, 0, 0, 1),
        ],
        datetime.time(10, 0),
        [0, 1],
    ),
    Case(
        "timetz_value",
        sqlalchemy.Time(timezone=True),
        sqlalchemy.Time(timezone=True),
        operator.le,
        # 04:00 and 05:00 UTC.
        [datetime.time(9, 0, tzinfo=_PLUS_5), datetime.time(10, 0, tzinfo=_PLUS_5)],
        datetime.time(4, 30, tzinfo=datetime.UTC),
        [0],
    ),
    Case(
        "timestamp_value",
        sqlalchemy.DateTime(),
        sqlalchemy.DateTime,
        operator.le,
        [
            datetime.datetime(2024, 1, 2, 3, 4, 5),
            datetime.datetime(2024, 1, 2, 3, 4, 5, 1),
        ],
        datetime.datetime(2024, 1, 2, 3, 4, 5),
        [0],
    ),
    Case(
        "timestamptz_value",
        sqlalchemy.DateTime(timezone=True),
        sqlalchemy.DateTime(timezone=True),
        operator.le,
        [
            datetime.datetime(2024, 1, 1, 22, 0, tzinfo=datetime.UTC),
            datetime.datetime(2024, 1, 1, 22, 0, 1, tzinfo=datetime.UTC),
        ],
        # The same instant as the first row.
        datetime.datetime(2024, 1, 2, 3, 0, tzinfo=_PLUS_5),
        [0],
    ),
    # Casting an aware datetime to a timestamp *without* time zone discards
    # its offset, so it is compared by its local wall-clock time.
    Case(
        "aware_timestamp_value",
        sqlalchemy.DateTime(),
        sqlalchemy.DateTime,
        operator.eq,
        [
            datetime.datetime(2024, 1, 1, 22, 0),
            datetime.datetime(2024, 1, 2, 3, 0),
        ],
        datetime.datetime(2024, 1, 2, 3, 0, tzinfo=_PLUS_5),
        [1],
    ),
    Case(
        "enum_value",
        _COLOR_ENUM,
        _COLOR_ENUM,
        operator.eq,
        [Color.red, Color.blue],
        Color.blue,
        [1],
    ),
    Case(
        "int_enum_value",
        sqlalchemy.Integer(),
        sqlalchemy.Integer,
        operator.le,
        [1, 2, 3, 4],
        Level.high,
        [0, 1, 2],
    ),
]


class Base(orm.DeclarativeBase):
    pass


register.base_wrapper(Base)


class TypedValue(Base):
    __abstract__ = True

    id: orm.Mapped[int] = orm.mapped_column(sqlalchemy.Integer, primary_key=True)


def _policy(case: Case) -> policy.Policy:
    return policy.Policy.from_sqla(
        expr=lambda x: case.compare(sql.column("value"), x),
        condition_args=[
            policy.ConditionArg(comparator_name=case.field, type=case.arg_type)
        ],
        cmd=policy.Command.select,
    )


def _model(case: Case) -> type[TypedValue]:
    return type(
        f"Typed_{case.field}",
        (TypedValue,),
        {
            "__tablename__": case.field,
            "value": orm.mapped_column(case.column_type),
            "__rls_policies__": [_policy(case)],
        },
    )


MODELS = {case.field: _model(case) for case in CASES}


class ContextTypesEndToEndTests(unittest.TestCase):
    postgresql: testing.postgresql.Postgresql
    admin_engine: sqlalchemy.engine.Engine
    engine: sqlalchemy.engine.Engine

    @classmethod
    def setUpClass(cls):
        cls.postgresql = testing.postgresql.Postgresql(
            postgres_args="-h 127.0.0.1 -F -c logging_collector=off"
        )
        url = sqlalchemy.engine.make_url(cls.postgresql.url()).set(
            drivername="postgresql+psycopg"
        )
        cls.admin_engine = sqlalchemy.create_engine(url)
        Base.metadata.create_all(cls.admin_engine)
        with cls.admin_engine.begin() as connection:
            create_policies.create_policies_no_commit(Base, connection)
            for case in CASES:
                connection.execute(
                    sqlalchemy.insert(MODELS[case.field]),
                    [{"id": i, "value": v} for i, v in enumerate(case.rows)],
                )
            connection.execute(
                sqlalchemy.text(
                    f"CREATE ROLE {_ROLE} LOGIN PASSWORD '{_ROLE}';"
                    f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {_ROLE};"
                )
            )
        cls.engine = sqlalchemy.create_engine(
            url.set(username=_ROLE, password=_ROLE),
            connect_args={"options": f"-c timezone={_SESSION_TIME_ZONE}"},
        )

    @classmethod
    def tearDownClass(cls):
        cls.engine.dispose()
        cls.admin_engine.dispose()
        cls.postgresql.stop()

    def _visible_ids(self, context: TypesContext, case: Case) -> list[int]:
        model = MODELS[case.field]
        with session.RlsSession(context=context, bind=self.engine) as sess:
            return list(
                sess.execute(sqlalchemy.select(model.id).order_by(model.id)).scalars()
            )

    def test_session_time_zone(self):
        with self.engine.connect() as connection:
            self.assertEqual(
                connection.execute(sqlalchemy.text("SHOW timezone")).scalar(),
                _SESSION_TIME_ZONE,
            )

    def test_context_values_are_cast_to_column_types(self):
        for case in CASES:
            with self.subTest(case.field):
                context = TypesContext(**{case.field: case.context_value})
                self.assertEqual(self._visible_ids(context, case), case.visible)

    def test_none_matches_no_rows(self):
        for case in CASES:
            with self.subTest(case.field):
                self.assertEqual(self._visible_ids(TypesContext(), case), [])


if __name__ == "__main__":
    unittest.main()
