from . import _sql_gen
from . import schemas


def policy_changed_checker(
    db_policy: schemas.Policy, metadata_policy: schemas.Policy
) -> bool:
    temp_metadata_policy = metadata_policy.model_copy()
    temp_metadata_policy.expression = _sql_gen.add_bypass_rls_to_expr(
        metadata_policy.expression
    )

    if isinstance(temp_metadata_policy.cmd, list):
        temp_metadata_policy.cmd = schemas.Command(temp_metadata_policy.cmd[0])

    return bool(db_policy == temp_metadata_policy)
