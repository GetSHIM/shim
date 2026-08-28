from typing import Literal, Self

from pydantic import AwareDatetime, model_validator

from .ids import ApiKeyId, UserId
from . import FrozenContractModel


ActorType = Literal["api_key", "user_jwt", "internal"]


def validate_actor_identity(
    actor_type: ActorType,
    api_key_id: ApiKeyId | None,
    user_id: UserId | None,
) -> None:
    valid = (
        actor_type == "api_key"
        and api_key_id is not None
        or actor_type == "user_jwt"
        and user_id is not None
        and api_key_id is None
        or actor_type == "internal"
        and api_key_id is None
        and user_id is None
    )
    if not valid:
        raise ValueError(f"invalid identity fields for actor_type={actor_type!r}")


class AuthenticatedPrincipal(FrozenContractModel):
    actor_type: ActorType
    api_key_id: ApiKeyId | None = None
    user_id: UserId | None = None
    authenticated_at: AwareDatetime

    @model_validator(mode="after")
    def validate_actor_shape(self) -> Self:
        validate_actor_identity(self.actor_type, self.api_key_id, self.user_id)
        return self
