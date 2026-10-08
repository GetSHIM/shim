from contextvars import ContextVar
from typing import NewType
from uuid import UUID


TenantId = NewType("TenantId", UUID)
UserId = NewType("UserId", UUID)
ApiKeyId = NewType("ApiKeyId", UUID)

RequestId = NewType("RequestId", str)
ProviderId = NewType("ProviderId", str)
ModelId = NewType("ModelId", str)
SecretRef = NewType("SecretRef", str)

# The request the gateway is serving in this task, once it has one. Error
# handlers read it so every refusal names the request the caller should quote.
CURRENT_REQUEST_ID: ContextVar[str | None] = ContextVar("shim_request_id", default=None)
