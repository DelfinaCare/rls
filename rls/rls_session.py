from sqlalchemy.orm.session import Session
from sqlalchemy import text
from pydantic import BaseModel
from typing import Optional


class RlsSession(Session):
    def __init__(self, context: Optional[BaseModel], *args, **kwargs):
        super().__init__(*args, **kwargs)
        if context is not None:
            self.context = context

    def setContext(self, context: BaseModel):
        self.context = context

    def _get_set_statements(self):
        stmts = []
        if self.context is None:
            return None

        for key, value in self.context.model_dump().items():
            # TODO: ask whether we set the rls. or not
            stmt = text(f"SET rls.{key} = {value};")
            stmts.append(stmt)
        return stmts

    def _execute_set_statements(self):
        stmts = self._get_set_statements()
        if stmts is not None:
            for stmt in stmts:
                super().execute(stmt)

    def get_context(self):
        return self.context

    def set_context(self, context):
        self.context = context

    def execute(self, *args, **kwargs):
        self._execute_set_statements()
        return super().execute(*args, **kwargs)
