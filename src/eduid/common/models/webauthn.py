from pydantic import BaseModel


class WebauthnChallenge(BaseModel):
    webauthn_options: str
