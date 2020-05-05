# -*- coding: utf-8 -*-
#
# Copyright (c) 2020 SUNET
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
from enum import Enum, unique
from typing import Optional, Union


@unique
class TranslatableMsg(Enum):
    """
    Messages sent to the front end with information on the results of the
    attempted operations on the back end.
    """


def success_message(message: Union[TranslatableMsg, str], data: Optional[dict] = None) -> dict:
    """
    Make a dict that corresponds to a success response, that can be marshalled into a response
    that eduid-front understands.

    :param message: the code that will be translated in eduid-front into a message to the user.
                    can be an TranslatableMsg instance or, for B/C and robustness, a str.
    :param data: any additional data the views may need to send in the response.
    """
    if isinstance(message, TranslatableMsg):
        message = str(message.value)
    msg = {'_status': 'ok', 'message': message}
    if data is not None:
        msg['data'] = data
    return msg


def error_message(message: Union[TranslatableMsg, str], errors: Optional[dict] = None) -> dict:
    """
    Make a dict that corresponds to an error response, that can be marshalled into a response
    that eduid-front understands.

    :param message: the code that will be translated in eduid-front into a message to the user.
                    can be an TranslatableMsg instance or, for B/C and robustness, a str.
    :param errors: an errors dict corresponding to a form in the front.
    """
    if isinstance(message, TranslatableMsg):
        message = str(message.value)
    msg = {'_status': 'error', 'message': message}
    if errors is not None:
        msg['errors'] = errors
    return msg
