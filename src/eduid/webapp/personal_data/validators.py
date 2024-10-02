from marshmallow import ValidationError

from eduid.webapp.personal_data.app import current_pdata_app as current_app
from eduid.webapp.personal_data.helpers import PDataMsg


def validate_language(lang: str) -> None:
    available_langs = current_app.conf.available_languages
    if lang not in available_langs:
        raise ValidationError(f"Language {lang!r} is not available")


def validate_nonempty(value: str) -> None:
    if not value.strip():  # Remove whitespace
        raise ValidationError(PDataMsg.required.value)
