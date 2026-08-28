"""Enterprise gateway error responses."""

from typing import NoReturn

from fastapi import HTTPException


def raise_persistence_error() -> NoReturn:
    raise HTTPException(
        status_code=503,
        detail={
            "code": "INTERNAL_ERROR",
            "message": "Gateway state could not be persisted.",
        },
    ) from None


def raise_audit_intent_error() -> NoReturn:
    raise HTTPException(
        status_code=503,
        detail={
            "code": "AUDIT_INTENT_FAILED",
            "message": "The required audit intent could not be persisted.",
            "retryable": True,
            "provider": None,
        },
    ) from None


def raise_accounting_limit(code: str) -> NoReturn:
    raise HTTPException(
        status_code=429,
        detail={
            "code": code,
            "message": "The request exceeds the current account limit.",
        },
    ) from None


def raise_tenant_policy_error() -> NoReturn:
    raise HTTPException(
        status_code=503,
        detail={
            "code": "INTERNAL_ERROR",
            "message": "Gateway policy configuration is unavailable.",
        },
    ) from None
