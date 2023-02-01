from typing import Mapping, Optional

import respx
from httpx import Response, Request
from eduid.common.misc.timeutil import utc_now
from eduid.common.models.amapi_user import (
    UserUpdateEmailRequest,
    UserUpdateLanguageRequest,
    UserUpdateNameRequest,
    UserUpdatePhoneRequest,
)

from eduid.common.clients.gnap_client.testing import MockedSyncAuthAPIMixin
from eduid.userdb.userdb import AmDB
from eduid.userdb.mail import MailAddressList
from eduid.userdb.phone import PhoneNumberList
from eduid.userdb.user import User


class MockedAMAPIMixin(MockedSyncAuthAPIMixin):
    def start_mock_amapi(self, central_user_db: Optional[AmDB] = None, access_token_value: Optional[str] = None):
        self.start_mock_auth_api(access_token_value=access_token_value)
        self.central_user_db = central_user_db
        mocked_users = respx.mock(base_url="http://localhost/amapi", assert_all_called=False)

        mocked_users.put(url="/users/hubba-bubba/name", name="200_put_name").mock(
            side_effect=self._side_effect_update_name
        )
        mocked_users.put(url="/users/hubba-bubba/email", name="200_put_email").mock(
            side_effect=self._side_effect_update_email
        )
        mocked_users.put(url="/users/hubba-bubba/language", name="200_put_language").mock(
            side_effect=self._side_effect_update_language
        )

        mocked_users.start()
        self.addCleanup(mocked_users.stop)  # type: ignore

    def _side_effect_update(self, func_name: str) -> User:
        if self.central_user_db is None:
            raise ValueError(f"side affect '{func_name}' was called but self.amdb is None")
        return self.central_user_db.get_user_by_eppn("hubba-bubba")

    def _side_effect_update_name(self, request: Request) -> Response:
        db_user = self._side_effect_update(func_name="_side_effect_update_name")
        assert self.central_user_db is not None
        mock_request = UserUpdateNameRequest.parse_raw(request.content)

        db_user.given_name = mock_request.given_name
        db_user.surname = mock_request.surname
        db_user.display_name = mock_request.display_name
        self.central_user_db.save(user=db_user)
        return Response(200, text='{"status": "true"}')

    def _side_effect_update_email(self, request: Request) -> Response:
        db_user = self._side_effect_update(func_name="_side_effect_update_email")
        assert self.central_user_db is not None
        mock_request = UserUpdateEmailRequest.parse_raw(request.content)

        mail_addresses = [mail.to_dict() for mail in mock_request.mail_addresses]
        db_user = self.central_user_db.get_user_by_eppn("hubba-bubba")
        self.central_user_db.unverify_mail_aliases(user_id=db_user.user_id, mail_aliases=mail_addresses)

        db_user.mail_addresses = MailAddressList(elements=mock_request.mail_addresses)
        self.central_user_db.save(user=db_user)
        return Response(200, text='{"status": "true"}')

    def _side_effect_update_language(self, request: Request) -> Response:
        db_user = self._side_effect_update(func_name="_side_effect_update_language")
        assert self.central_user_db is not None
        mock_request = UserUpdateLanguageRequest.parse_raw(request.content)

        db_user.language = mock_request.language
        self.central_user_db.save(user=db_user)
        return Response(200, text='{"status": "true"}')

    def _side_effect_update_phone(self, request: Request) -> Response:
        db_user = self._side_effect_update(func_name="_side_effect_update_phone")
        assert self.central_user_db is not None
        mock_request = UserUpdatePhoneRequest.parse_raw(request.content)

        phones = [phone.to_dict() for phone in mock_request.phone_numbers]
        self.central_user_db.unverify_phones(user_id=db_user.user_id, phones=phones)
        db_user.phone_numbers = PhoneNumberList(elements=mock_request.phone_numbers)
        return Response(200, text='{"status": "true"}')

    def _side_effect_update_terminate(self, request: Request) -> Response:
        db_user = self._side_effect_update(func_name="_side_effect_update_terminate")
        assert self.central_user_db is not None

        db_user.terminated = utc_now()
        return Response(200, text='{"status": "true"}')
