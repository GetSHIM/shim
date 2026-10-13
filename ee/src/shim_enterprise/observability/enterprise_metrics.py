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
# Bounded: method is an MCP method name or "other"; tool a TOOLS name or "unknown".
MCP_METHOD_LABELS = frozenset(
    {
        "initialize",
        "server/discover",
        "ping",
        "tools/list",
        "tools/call",
        "prompts/list",
        "prompts/get",
        "resources/list",
        "resources/read",
        "notifications/initialized",
        "notifications/cancelled",
        "other",
    }
)
MCP_REQUESTS_TOTAL = Counter(
    "shim_mcp_requests_total",
    "MCP endpoint requests by method and outcome (ok, tool_error, protocol_error).",
    ("method", "outcome"),
)
MCP_TOOL_CALLS_TOTAL = Counter(
    "shim_mcp_tool_calls_total",
    "MCP tool calls by tool and outcome (ok, error).",
    ("tool", "outcome"),
)
RULE_PROPOSALS_TOTAL = Counter(
    "shim_rule_proposals_total",
    "Rule proposals by outcome: proposed, needs_examples, invalid, limited, file_managed.",
    ("outcome",),
)
REMEDIATIONS_TOTAL = Counter(
    "shim_remediations_total",
    "Unattended changes by allowlist entry (none for a skipped finding) and phase: "
    "applied, kept, restored, restore_skipped, skipped, undone.",
    ("entry", "phase"),
)
INFERENCE_SCRAPES_TOTAL = Counter(
    "shim_inference_metrics_scrapes_total",
    "Model server metrics reads by server (vllm, tgi, ollama) and outcome (ok, "
    "error, skipped).",
    ("server", "outcome"),
)
