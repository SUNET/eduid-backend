#
# Copyright (c) 2018 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import logging
from typing import AnyStr, Optional
from urllib.parse import quote, unquote

from bleach import clean
from flask import request

module_logger = logging.getLogger(__name__)


class SanitationProblem(Exception):
    pass


class Sanitizer(object):
    """
    Sanitize user inputs.
    """

    def sanitize_input(
        self,
        untrusted_text: AnyStr,
        content_type: Optional[str] = None,
        strip_characters: bool = False,
        logger: Optional[logging.Logger] = None,
    ) -> str:
        """
        Sanitize user input by escaping or removing potentially
        harmful input using a whitelist-based approach with
        bleach as recommended by OWASP.

        :param untrusted_text: User input to sanitize
        :param logger: logging facility
        :param content_type: Content type of the input to sanitize
        :param strip_characters: Set to True to remove instead of escaping potentially harmful input.

        :return: Sanitized user input
        """
        if logger is None:
            logger = module_logger
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
                logger,
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
        logger: logging.Logger,
        strip_characters: bool = False,
        content_type: Optional[str] = None,
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
        # if untrusted_text is None:
        #     # If we are given None then there's nothing to clean
        #     return None

        # Decide on whether or not to use percent encoding:
        # 1. Check if the content type has been explicitly set
        # 2. If set, use percent encoding if requested by the client
        # 3. If the content type has not been explicitly set,
        # 3.1 use percent encoding according to the calling
        #    functions preference or,
        # 3.2 use the default value as set in the function definition.
        if content_type is None and hasattr(request, "mimetype"):
            content_type = request.mimetype

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
            cleaned_text = self._safe_clean(decoded_text, logger, strip_characters)

            if decoded_text != cleaned_text:
                logger.warning("Some potential harmful characters were removed from untrusted user input.")

            if decoded_text != untrusted_text:
                # Note that at least '&' and '=' needs to be unencoded when using PySAML2
                return quote(cleaned_text, safe="?&=")

            return cleaned_text

        # If the untrusted_text is not percent encoded we only have to:
        # 1. Clean it to remove dangerous characters.

        cleaned_text = self._safe_clean(untrusted_text, logger, strip_characters)

        if untrusted_text != cleaned_text:
            logger.warning("Some potential harmful characters were removed from untrusted user input.")

        return cleaned_text

    def _safe_clean(self, untrusted_text: str, logger: logging.Logger, strip_characters: bool = False) -> str:
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
