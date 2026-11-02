import datetime
import decimal
import enum
import typing
import unittest
import uuid

import pydantic

from rls import session


class Role(str, enum.Enum):
    admin = "admin"


class StrRole(enum.StrEnum):
    admin = "admin"


class Level(enum.IntEnum):
    high = 3


class TupleEnum(enum.Enum):
    a = (1, 2)


def _params(context: pydantic.BaseModel) -> dict[str, str]:
    return session._context_to_value_params(
        context, list(type(context).model_fields.keys())
    )


class ContextSerializationTests(unittest.TestCase):
    def test_str_enum_mixin_serialized_by_value(self):
        class Context(pydantic.BaseModel):
            role: Role

        self.assertEqual(_params(Context(role=Role.admin)), {"value_role": "admin"})

    def test_strenum_serialized_by_value(self):
        class Context(pydantic.BaseModel):
            role: StrRole

        self.assertEqual(_params(Context(role=StrRole.admin)), {"value_role": "admin"})

    def test_int_enum_serialized_by_value(self):
        class Context(pydantic.BaseModel):
            level: Level

        self.assertEqual(_params(Context(level=Level.high)), {"value_level": "3"})

    def test_scalar_types(self):
        class Context(pydantic.BaseModel):
            uid: uuid.UUID
            when: datetime.datetime
            day: datetime.date
            amount: decimal.Decimal
            flag: bool
            name: str
            count: int
            literal: typing.Literal["a", "b"]

        uid = uuid.UUID("12345678-1234-5678-1234-567812345678")
        when = datetime.datetime(2024, 1, 2, 3, 4, 5, tzinfo=datetime.UTC)
        context = Context(
            uid=uid,
            when=when,
            day=datetime.date(2024, 1, 2),
            amount=decimal.Decimal("1.5"),
            flag=True,
            name="x",
            count=7,
            literal="a",
        )
        self.assertEqual(
            _params(context),
            {
                "value_uid": "12345678-1234-5678-1234-567812345678",
                "value_when": "2024-01-02 03:04:05+00:00",
                "value_day": "2024-01-02",
                "value_amount": "1.5",
                "value_flag": "True",
                "value_name": "x",
                "value_count": "7",
                "value_literal": "a",
            },
        )

    def test_optional_none_serialized_as_empty_string(self):
        class Context(pydantic.BaseModel):
            role: Role | None
            other: int | None

        self.assertEqual(
            _params(Context(role=None, other=None)),
            {"value_role": "", "value_other": ""},
        )

    def test_unsupported_runtime_value_raises(self):
        class Context(pydantic.BaseModel):
            account_id: int

        context = Context.model_construct(account_id=[1, 2])
        with self.assertRaises(TypeError):
            _params(context)


class ContextValidationTests(unittest.TestCase):
    def _assert_rejected(self, annotation: typing.Any) -> None:
        Context = pydantic.create_model("Context", field=(annotation, ...))
        with self.assertRaisesRegex(TypeError, "Context.field"):
            session.RlsSession(context=Context.model_construct(field=None))

    def test_list_rejected(self):
        self._assert_rejected(list[int])

    def test_optional_list_rejected(self):
        self._assert_rejected(list[int] | None)

    def test_dict_rejected(self):
        self._assert_rejected(dict[str, int])

    def test_any_rejected(self):
        self._assert_rejected(typing.Any)

    def test_nested_model_rejected(self):
        class Inner(pydantic.BaseModel):
            x: int

        self._assert_rejected(Inner)

    def test_enum_with_non_scalar_values_rejected(self):
        self._assert_rejected(TupleEnum)

    def test_supported_types_accepted(self):
        class Context(pydantic.BaseModel):
            role: Role
            level: Level | None
            uid: uuid.UUID
            when: datetime.datetime
            account_id: pydantic.PositiveInt

        session.RlsSession(
            context=Context(
                role=Role.admin,
                level=None,
                uid=uuid.uuid4(),
                when=datetime.datetime.now(),
                account_id=1,
            )
        )

    def test_async_session_validates(self):
        class Context(pydantic.BaseModel):
            ids: list[int]

        with self.assertRaises(TypeError):
            session.AsyncRlsSession(context=Context(ids=[1]))


if __name__ == "__main__":
    unittest.main()
