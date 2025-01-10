from typing import Optional

from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session


class RlsSession(Session):
    def __init__(self, context: Optional[BaseModel] = None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rls_bypass = False  # Track RLS bypass state
        if context is not None:
            self.context = context

    def bypass_rls(self):
        """
        Context manager to bypass RLS.
        Usage: with session.bypass_rls() as session:
        """
        return self.BypassRLSContext(self)

    def _get_set_statements(self):
        """
        Generates SQL SET statements based on the context model.
        """
        stmts = []
        if self.context is None or self._rls_bypass:  # Skip RLS statements if bypassed
            return None

        for key, value in self.context.model_dump().items():
            stmt = text(f"SET rls.{key} = {value};")
            stmts.append(stmt)
        return stmts

    def _execute_set_statements(self):
        """
        Executes the RLS SET statements unless bypassing RLS.
        """
        if self._rls_bypass:  # Skip setting RLS when bypassing
            return
        stmts = self._get_set_statements()
        if stmts is not None:
            for stmt in stmts:
                super().execute(stmt)

    def get_context(self):
        return self.context

    def set_context(self, context):
        self.context = context

    def execute(self, *args, **kwargs):
        """
        Executes SQL queries, applying RLS unless bypassing.
        """
        self._execute_set_statements()
        return super().execute(*args, **kwargs)

    # Inner class for the context manager
    # Updated BypassRLSContext to handle errors
    class BypassRLSContext:
        def __init__(self, session: "RlsSession"):
            self.session = session

        def __enter__(self):
            """
            When entering the context, attempt to bypass RLS.
            If the command fails, rollback the transaction.
            """
            self.session._rls_bypass = True
            # Disable row-level security
            self.session.execute(text("SET LOCAL rls.bypass_rls = true;"))
            return self.session

        def __exit__(self, exc_type, exc_val, exc_tb):
            """
            When exiting the context, restore RLS if it was successfully disabled.
            """
            self.session._rls_bypass = False

            # If the transaction failed, skip re-enabling RLS
            if exc_type is not None:
                self.session.rollback()
                return
            self.session.execute(text("SET LOCAL rls.bypass_rls = false;"))

        def execute(self, *args, **kwargs):
            return self.session.execute(*args, **kwargs)
