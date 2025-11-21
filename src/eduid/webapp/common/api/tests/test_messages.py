from enum import unique
from typing import ClassVar
from unittest import TestCase

from eduid.webapp.common.api.messages import (
    CommonMsg,
    TranslatableMsg,
    error_response,
    make_query_string,
    redirect_with_msg,
    success_response,
)
from eduid.webapp.common.api.schemas.models import FluxResponseStatus


@unique
class TestsMsg(TranslatableMsg):
    __test__: ClassVar[bool] = False
    fst_test_msg = "test.first_msg"
    snd_test_msg = "test.second_msg"


class MessageTests(TestCase):
    def test_success_message(self) -> None:
        message = success_response(message=TestsMsg.fst_test_msg)
        assert message.status == FluxResponseStatus.OK
        assert message.payload == dict(message=TestsMsg.fst_test_msg.value, success=True)

    def test_success_message_with_data(self) -> None:
        data = {"email": "test@example.com"}
        message = success_response(payload=data, message=TestsMsg.fst_test_msg)
        assert message.status == FluxResponseStatus.OK
        assert message.payload == dict(message=TestsMsg.fst_test_msg.value, success=True, email="test@example.com")

    def test_success_message_from_str(self) -> None:
        message = success_response(message="test.str_msg")
        assert message.status == FluxResponseStatus.OK
        assert message.payload == dict(message="test.str_msg", success=True)

    def test_success_message_from_str_with_data(self) -> None:
        data = {"email": "test@example.com"}
        message = success_response(payload=data, message="test.str_msg")
        assert message.status == FluxResponseStatus.OK
        assert message.payload == dict(message="test.str_msg", success=True, email="test@example.com")

    def test_success_message_unknown(self) -> None:
        with self.assertRaises(AttributeError):
            success_response(TestsMsg.unknown_msg)  # type: ignore[attr-defined]

    def test_success_message_unknown_with_data(self) -> None:
        data = {"email": "test@example.com"}
        with self.assertRaises(AttributeError):
            success_response(payload=data, message=TestsMsg.unknown_msg)  # type: ignore[attr-defined]

    def test_error_message(self) -> None:
        message = error_response(message=TestsMsg.fst_test_msg)
        assert message.status == FluxResponseStatus.ERROR
        assert message.payload == dict(message=TestsMsg.fst_test_msg.value, success=False)

    def test_error_message_with_errors(self) -> None:
        data = {"errors": {"email": "required"}}
        message = error_response(payload=data, message=TestsMsg.fst_test_msg)
        assert message.status == FluxResponseStatus.ERROR
        assert message.payload == dict(message=TestsMsg.fst_test_msg.value, success=False, errors=data["errors"])

    def test_error_message_with_status(self) -> None:
        data = {"status": "stale"}
        message = error_response(payload=data, message=TestsMsg.fst_test_msg)
        assert message.status == FluxResponseStatus.ERROR
        assert message.payload == dict(message=TestsMsg.fst_test_msg.value, success=False, status=data["status"])

    def test_error_message_with_next(self) -> None:
        data = {"next": "/next"}
        message = error_response(payload=data, message=TestsMsg.fst_test_msg)
        assert message.status == FluxResponseStatus.ERROR
        assert message.payload == dict(message=TestsMsg.fst_test_msg.value, success=False, next=data["next"])

    def test_error_message_from_str(self) -> None:
        message = error_response(message="test.str_msg")
        assert message.status == FluxResponseStatus.ERROR
        assert message.payload == dict(message="test.str_msg", success=False)

    def test_error_message_from_str_with_errors(self) -> None:
        data = {"errors": {"email": "required"}}
        message = error_response(payload=data, message="str_msg")
        assert message.status == FluxResponseStatus.ERROR
        assert message.payload == dict(message="str_msg", success=False, errors=data["errors"])

    def test_error_message_from_str_with_status(self) -> None:
        data = {"status": "stale"}
        message = error_response(payload=data, message="str_msg")
        assert message.status == FluxResponseStatus.ERROR
        assert message.payload == dict(message="str_msg", success=False, status=data["status"])

    def test_error_message_from_str_with_next(self) -> None:
        data = {"next": "/next"}
        message = error_response(payload=data, message="str_msg")
        assert message.status == FluxResponseStatus.ERROR
        assert message.payload == dict(message="str_msg", success=False, next=data["next"])

    def test_error_message_unknown(self) -> None:
        with self.assertRaises(AttributeError):
            error_response(TestsMsg.unknown_msg)  # type: ignore[attr-defined]

    def test_make_query_string_error(self) -> None:
        qs = make_query_string(TestsMsg.fst_test_msg)
        self.assertEqual(qs, "msg=%3AERROR%3Atest.first_msg")

    def test_make_query_string_success(self) -> None:
        qs = make_query_string(TestsMsg.fst_test_msg, error=False)
        self.assertEqual(qs, "msg=test.first_msg")

    def test_make_query_string_error_unknown(self) -> None:
        with self.assertRaises(AttributeError):
            make_query_string(TestsMsg.unknown_msg)  # type: ignore[attr-defined]

    def test_make_query_string_success_unknown(self) -> None:
        with self.assertRaises(AttributeError):
            make_query_string(TestsMsg.unknown_msg, error=False)  # type: ignore[attr-defined]

    def test_make_redirect_error(self) -> None:
        url = "https://example.com"
        response = redirect_with_msg(url, TestsMsg.fst_test_msg)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "https://example.com?msg=%3AERROR%3Atest.first_msg")

    def test_make_redirect_error_with_str(self) -> None:
        url = "https://example.com"
        response = redirect_with_msg(url, "test.str_msg")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "https://example.com?msg=%3AERROR%3Atest.str_msg")

    def test_make_redirect_success(self) -> None:
        url = "https://example.com"
        response = redirect_with_msg(url, TestsMsg.fst_test_msg, error=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "https://example.com?msg=test.first_msg")

    def test_make_redirect_success_with_str(self) -> None:
        url = "https://example.com"
        response = redirect_with_msg(url, "test.str_msg", error=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "https://example.com?msg=test.str_msg")


class MessagesTests(TestCase):
    def test_messages(self) -> None:
        """"""
        self.assertEqual(CommonMsg.temp_problem.value, "Temporary technical problems")
        self.assertEqual(CommonMsg.form_errors.value, "form-errors")
        self.assertEqual(CommonMsg.out_of_sync.value, "user-out-of-sync")
        self.assertEqual(CommonMsg.navet_error.value, "error_navet_task")
        self.assertEqual(CommonMsg.nin_invalid.value, "nin needs to be formatted as 18|19|20yymmddxxxx")
        self.assertEqual(CommonMsg.email_invalid.value, "email needs to be formatted according to RFC2822")
        self.assertEqual(CommonMsg.csrf_try_again.value, "csrf.try_again")
        self.assertEqual(CommonMsg.csrf_missing.value, "csrf.missing")
