"""Prometheus instruments for enterprise-only operations."""

from prometheus_client import Counter, Gauge


QUOTA_RESERVATION_TOTAL = Counter(
    "quota_reservation_total",
    "Durable quota reservation outcomes.",
    ("status",),
)
USAGE_SETTLEMENT_TOTAL = Counter(
    "usage_settlement_total",
    "Durable usage settlement outcomes.",
    ("status",),
)
OUTBOX_LAG_SECONDS = Gauge(
    "outbox_lag_seconds",
    "Age of the oldest undelivered outbox event.",
    ("event_type",),
)
OUTBOX_DEAD_LETTER_TOTAL = Counter(
    "outbox_dead_letter_total",
    "Outbox events moved to dead letter.",
    ("event_type",),
)
AUDIT_WORKER_LAG_SECONDS = Gauge(
    "audit_worker_lag_seconds",
    "Age of the oldest undelivered audit event observed by the worker.",
)
REQUEST_APPROVALS_TOTAL = Counter(
    "shim_request_approvals_total",
    "Approval gate outcomes for requests a tenant rule holds.",
    ("outcome",),
)
REQUEST_APPROVAL_DECISIONS_TOTAL = Counter(
    "shim_request_approval_decisions_total",
    "Administrator decisions on held requests.",
    ("decision",),
)
REQUEST_ARCHIVE_WRITES_TOTAL = Counter(
    "shim_request_archive_writes_total",
    "Request archive writes: stored, skipped_size or failed.",
    ("result",),
)
LICENSE_DAYS_REMAINING = Gauge(
    "license_days_remaining",
    "Days until the enterprise licence expires; negative inside the grace period.",
)
