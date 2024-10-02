from typing import Any

from marshmallow import Schema, ValidationError

__author__ = "lundberg"

from eduid.webapp.common.api.validation import is_valid_password


class PasswordSchema(Schema):
    class Meta:
        zxcvbn_terms: list[str] | None = None
        min_entropy: int | None = None
        min_score: int | None = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.Meta.zxcvbn_terms = kwargs.pop("zxcvbn_terms", [])
        self.Meta.min_entropy = kwargs.pop("min_entropy")
        self.Meta.min_score = kwargs.pop("min_score")
        super().__init__(*args, **kwargs)

    def validate_password(self, password: str, **kwargs: Any) -> None:
        """
        :param password: New password

        Checks the complexity of the password
        """
        if self.Meta.zxcvbn_terms is None or self.Meta.min_entropy is None or self.Meta.min_score is None:
            raise ValidationError("The password complexity cannot be determined.")
        try:
            if not is_valid_password(
                password=password,
                user_info=self.Meta.zxcvbn_terms,
                min_entropy=self.Meta.min_entropy,
                min_score=self.Meta.min_score,
            ):
                raise ValidationError("The password complexity is too weak.")
        except ValueError:
            raise ValidationError("The password complexity is too weak.")
