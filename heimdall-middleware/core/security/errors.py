"""One error envelope for the whole API, so the UI can always explain a failure."""
from __future__ import annotations

from typing import Optional

from fastapi import HTTPException


def api_error(status: int, code: str, message: str, hint: str = "",
              retry_after: Optional[int] = None) -> HTTPException:
    detail = {"code": code, "message": message}
    if hint:
        detail["hint"] = hint
    if retry_after is not None:
        detail["retry_after"] = retry_after
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else None
    return HTTPException(status_code=status, detail=detail, headers=headers)
