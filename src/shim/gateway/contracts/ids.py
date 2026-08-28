from typing import NewType
from uuid import UUID


TenantId = NewType("TenantId", UUID)
UserId = NewType("UserId", UUID)
ApiKeyId = NewType("ApiKeyId", UUID)

RequestId = NewType("RequestId", str)
ProviderId = NewType("ProviderId", str)
ModelId = NewType("ModelId", str)
SecretRef = NewType("SecretRef", str)
