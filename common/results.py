"""Shared shape for scanner module results."""


def module_result(module_name: str, target_url: str, **fields) -> dict:
    """Result dict every module returns: identity, its own fields, and the
    `errors` list modules append to instead of raising."""
    return {"module": module_name, "target": target_url, **fields, "errors": []}
