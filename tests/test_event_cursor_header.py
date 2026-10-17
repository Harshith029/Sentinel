"""Validation for the browser's SSE resumption cursor."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from sentinel.control.app import _resolve_start_id


def test_last_event_id_header_overrides_the_query_cursor() -> None:
    request = SimpleNamespace(headers={"last-event-id": "17"})
    assert _resolve_start_id(request, 3) == 17


@pytest.mark.parametrize("header", ["--5", "-5", "5.0", " 5", "\U0001d7dd"])
def test_last_event_id_header_rejects_non_decimal_values(header: str) -> None:
    request = SimpleNamespace(headers={"last-event-id": header})
    with pytest.raises(HTTPException, match="non-negative integer") as error:
        _resolve_start_id(request, 3)
    assert error.value.status_code == 422
