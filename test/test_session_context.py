import datetime
import decimal
import enum
import typing
import unittest
import uuid

import pydantic

from rls import session
from rls import session_context


class Role(str, enum.Enum):
    admin = "admin"


class StrRole(enum.StrEnum):
    admin = "admin"


class Level(enum.IntEnum):
    high = 3


class TupleEnum(enum.Enum):
    a = (1, 2)


AccountId = typing.NewType("AccountId", int)


def _params(context: pydantic.BaseModel) -> dict[str, str]:
    return session_context.render_values_function(type(context))(context)


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


class OptionalContextTests(unittest.TestCase):
    """Every spelling of an optional field renders None as '' and a value
    the same way as the non-optional type."""

    OPTIONAL_INT_ANNOTATIONS: typing.ClassVar[dict[str, typing.Any]] = {
        "pep604": int | None,
        "pep604_none_first": None | int,
        "typing_optional": typing.Optional[int],  # noqa: UP045
        "typing_union": typing.Union[int, None],  # noqa: UP007
        "annotated_outside": typing.Annotated[int | None, pydantic.Field(ge=0)],
        "annotated_inside": typing.Annotated[int, pydantic.Field(ge=0)] | None,
        "positive_int": pydantic.PositiveInt | None,
        "new_type": AccountId | None,
        "nested_optional": typing.Optional[int | None],  # noqa: PYI016, UP045
    }

    def _model(self, annotation: typing.Any) -> type[pydantic.BaseModel]:
        return pydantic.create_model("Context", value=(annotation, None))

    def test_optional_int_spellings(self):
        for name, annotation in self.OPTIONAL_INT_ANNOTATIONS.items():
            with self.subTest(name):
                Context = self._model(annotation)
                self.assertEqual(_params(Context(value=None)), {"value_value": ""})
                self.assertEqual(_params(Context()), {"value_value": ""})
                self.assertEqual(_params(Context(value=5)), {"value_value": "5"})

    def test_optional_enum_spellings(self):
        for name, annotation, value, rendered in [
            ("pep604", Role | None, Role.admin, "admin"),
            ("typing_optional", typing.Optional[Role], Role.admin, "admin"),  # noqa: UP045
            (
                "annotated_inside",
                typing.Annotated[Role, "meta"] | None,
                "admin",
                "admin",
            ),
            ("str_enum", StrRole | None, StrRole.admin, "admin"),
            ("int_enum", Level | None, 3, "3"),
        ]:
            with self.subTest(name):
                Context = self._model(annotation)
                self.assertEqual(_params(Context(value=None)), {"value_value": ""})
                self.assertEqual(
                    _params(Context(value=value)), {"value_value": rendered}
                )

    def test_optional_union_of_enum_and_scalar(self):
        Context = self._model(Role | int | None)
        self.assertEqual(_params(Context(value=Role.admin)), {"value_value": "admin"})
        self.assertEqual(_params(Context(value=4)), {"value_value": "4"})
        self.assertEqual(_params(Context(value=None)), {"value_value": ""})

    def test_optional_other_scalars(self):
        uid = uuid.UUID("12345678-1234-5678-1234-567812345678")
        for annotation, value, rendered in [
            (uuid.UUID | None, uid, str(uid)),
            (str | None, "x", "x"),
            (bool | None, False, "False"),
            (datetime.date | None, datetime.date(2024, 1, 2), "2024-01-02"),
        ]:
            with self.subTest(annotation):
                Context = self._model(annotation)
                self.assertEqual(
                    _params(Context(value=value)), {"value_value": rendered}
                )
                self.assertEqual(_params(Context(value=None)), {"value_value": ""})

    @unittest.skipUnless(hasattr(typing, "TypeAliasType"), "requires Python 3.12+")
    def test_type_alias(self):
        MaybeId = typing.TypeAliasType("MaybeId", int | None)  # type: ignore[attr-defined]
        Context = self._model(MaybeId)
        self.assertEqual(_params(Context(value=None)), {"value_value": ""})
        self.assertEqual(_params(Context(value=7)), {"value_value": "7"})

    def test_optional_falsy_values_are_not_treated_as_none(self):
        Context = self._model(int | None)
        self.assertEqual(_params(Context(value=0)), {"value_value": "0"})
        Context = self._model(str | None)
        self.assertEqual(_params(Context(value="")), {"value_value": ""})

    def test_session_accepts_optional_spellings(self):
        for name, annotation in self.OPTIONAL_INT_ANNOTATIONS.items():
            with self.subTest(name):
                session.RlsSession(context=self._model(annotation)(value=None))


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

    def test_literal_rejected(self):
        self._assert_rejected(typing.Literal["a", "b"])

    def test_optional_annotated_list_rejected(self):
        self._assert_rejected(typing.Annotated[list[int], "meta"] | None)

    def test_none_only_rejected(self):
        self._assert_rejected(None)

    def test_none_type_only_rejected(self):
        self._assert_rejected(type(None))

    def test_optional_literal_rejected(self):
        self._assert_rejected(typing.Literal[Role.admin] | None)

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
