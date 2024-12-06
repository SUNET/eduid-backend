import logging
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, AnyStr
from urllib.parse import quote, unquote

from bleach import clean
from werkzeug.exceptions import BadRequest

logger = logging.getLogger(__name__)


class SanitationProblem(Exception):
    pass


class Sanitizer:
    """
    Sanitize user inputs.
    """

    def sanitize_input(
        self,
        untrusted_text: AnyStr,
        content_type: str | None = None,
        strip_characters: bool = False,
    ) -> str:
        """
        Sanitize user input by escaping or removing potentially
        harmful input using a whitelist-based approach with
        bleach as recommended by OWASP.

        :param untrusted_text: User input to sanitize
        :param content_type: Content type of the input to sanitize
        :param strip_characters: Set to True to remove instead of escaping potentially harmful input.

        :return: Sanitized user input
        """
        try:
            # Test if the untrusted text is percent encoded before running bleach.
            _untrusted_text: str
            if isinstance(untrusted_text, bytes):
                _untrusted_text = untrusted_text.decode("utf-8")
            else:
                _untrusted_text = untrusted_text

            use_percent_encoding = unquote(untrusted_text) != untrusted_text

            return self._sanitize_input(
                _untrusted_text,
                strip_characters=strip_characters,
                content_type=content_type,
                percent_encoded=use_percent_encoding,
            )

        except UnicodeDecodeError:
            logger.warning(
                "A malicious user tried to crash the application by sending non-unicode input in a GET request"
            )
            raise SanitationProblem("Non-unicode input")

    def _sanitize_input(
        self,
        untrusted_text: str,
        strip_characters: bool = False,
        content_type: str | None = None,
        percent_encoded: bool = False,
    ) -> str:
        """
        :param untrusted_text: User input to sanitize
        :param strip_characters: Set to True to remove instead of escaping
                                 potentially harmful input.

        :param content_type: Set to decide on the use of percent encoding
                             according to the content type.

        :param percent_encoded: Set to True if the input should be treated
                                as percent encoded if no content type is
                                already defined.

        :return: Sanitized user input
        """

        # Decide on whether to use percent encoding:
        # 1. Check if the content type has been explicitly set
        # 2. If set, use percent encoding if requested by the client
        # 3. If the content type has not been explicitly set,
        # 3.1 use percent encoding according to the calling
        #    functions preference or,
        # 3.2 use the default value as set in the function definition.
        if isinstance(content_type, str) and content_type:
            if content_type == "application/x-www-form-urlencoded":
                use_percent_encoding = True
            else:
                use_percent_encoding = False

        else:
            use_percent_encoding = percent_encoded

        if use_percent_encoding:
            # If the untrusted_text is percent encoded we have to:
            # 1. Decode it so we can process it.
            # 2. Clean it to remove dangerous characters.
            # 3. Percent encode, if needed, and returning it back.

            decoded_text = unquote(untrusted_text)
            cleaned_text = self._safe_clean(decoded_text, strip_characters)

            if decoded_text != cleaned_text:
                logger.warning("Some potential harmful characters were removed from untrusted user input.")

            if decoded_text != untrusted_text:
                # Note that at least '&' and '=' needs to be unencoded when using PySAML2
                return quote(cleaned_text, safe="?&=")

            return cleaned_text

        # If the untrusted_text is not percent encoded we only have to:
        # 1. Clean it to remove dangerous characters.

        cleaned_text = self._safe_clean(untrusted_text, strip_characters)

        if untrusted_text != cleaned_text:
            logger.warning("Some potential harmful characters were removed from untrusted user input.")

        return cleaned_text

    @staticmethod
    def _safe_clean(untrusted_text: str, strip_characters: bool = False) -> str:
        """
        Wrapper for the clean function of bleach to be able
        to catch when illegal UTF-8 is processed.

        :param untrusted_text: Text to sanitize
        :param strip_characters: Set to True to remove instead of escaping
        :return: Sanitized text
        """
        try:
            return clean(untrusted_text, strip=strip_characters)
        except KeyError:
            logger.warning(
                "A malicious user tried to crash the application by "
                "sending illegal UTF-8 in an URI or other untrusted "
                "user input."
            )
            raise SanitationProblem("Illegal UTF-8")


def sanitize_map(data: Mapping[str, Any]) -> dict[str, Any]:
    return {str(sanitize_item(k)): sanitize_item(v) for k, v in data.items()}


def sanitize_iter(data: Iterable[str] | Iterable[Sequence[Any]]) -> list[str | dict[str, Any] | list[Any] | None]:
    return [sanitize_item(item) for item in data]


def sanitize_item(
    data: str | dict[str, Any] | Sequence[Any] | list[Sequence[Any]] | None,
) -> str | dict[str, Any] | list[Any] | None:
    match data:
        case None:
            return None
        case dict():
            return sanitize_map(data)
        case list():
            return sanitize_iter(data)
        case str():
            san = Sanitizer()
            try:
                assert isinstance(data, str)
                safe_data = san.sanitize_input(data)
                if safe_data != data:
                    logger.warning("Sanitized input from unsafe characters")
                    logger.debug(f"data: {data} -> safe_data: {safe_data}")
            except SanitationProblem:
                logger.exception("There was a problem sanitizing inputs")
                raise BadRequest()
            return str(safe_data)
        case _:
            raise SanitationProblem(f"incompatible type {type(data)}")
