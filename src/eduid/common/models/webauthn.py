from typing import Any

from pydantic import BaseModel


class WebauthnChallenge(BaseModel):
    webauthn_options: dict[str, Any]
