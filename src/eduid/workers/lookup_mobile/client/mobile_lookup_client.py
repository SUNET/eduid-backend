from suds.client import Client

from eduid.common.config.base import EduidEnvironment
from eduid.common.config.workers import MobConfig
from eduid.common.decorators import deprecated
from eduid.workers.lookup_mobile.decorators import TransactionAudit
from eduid.workers.lookup_mobile.development.development_search_result import _get_devel_search_result
from eduid.workers.lookup_mobile.utilities import format_mobile_number, format_NIN


class MobileLookupClient:
    def __init__(self, logger, config: MobConfig) -> None:
        self.conf = config

        # enable transaction logging if configured
        self.transaction_audit = self.conf.transaction_audit and self.conf.mongo_uri

        self._client: Client | None = None
        self.logger = logger

    @property
    def client(self) -> Client:
        if not self._client:
            self._client = Client(self.conf.teleadress_client_url, port=self.conf.teleadress_client_port)
        return self._client

    def _get_find_person(self):
        find_person = self.client.factory.create("ns7:FindPersonClass")
        find_person.QueryParams = self.client.factory.create("ns7:QueryParamsClass")
        find_person.QueryColumns = self.client.factory.create("ns7:QueryColumnsClass")
        return find_person

    @TransactionAudit()
    @deprecated("This task seems unused")
    def find_mobiles_by_NIN(self, national_identity_number: str, number_region=None) -> list[str]:
        formatted_nin = format_NIN(national_identity_number)
        if not formatted_nin:
            self.logger.error(f"Invalid NIN input: {national_identity_number}")
            return []

        mobiles = self._search_by_SSNo(formatted_nin)

        if not mobiles:
            self.logger.debug(f"Did not get search result from nin: {formatted_nin}")
            return []

        return format_mobile_number(mobiles, number_region)

    @TransactionAudit()
    def find_NIN_by_mobile(self, mobile_number) -> str | None:
        nin = self._search_by_mobile(mobile_number)
        if not nin:
            self.logger.debug(f"Did not get search result from mobile number: {mobile_number}")
            return None

        return format_NIN(nin)

    def _search(self, param):
        # Start the search
        # TODO: remove self.conf.devel_mode, use environment instead
        if self.conf.testing or self.conf.environment == EduidEnvironment.dev:
            result = _get_devel_search_result(param)
        else:
            result = self.client.service.Find(param)

        if result._error_code != 0:
            self.logger.debug(
                "Error code: {err_code}, error message: {err_message}".format(
                    err_code=result._error_code, err_message=(result._error_text.encode("utf-8"))
                )
            )
            return None

        # Check if the search got a hit
        if result.record_list[0]._num_records < 1:
            return None

        return result.record_list[0].record

    @deprecated("This function seems unused")
    def _search_by_SSNo(self, national_identity_number: str) -> list[str]:
        person_search = self._get_find_person()

        # Set the eduid user id and password
        person_search._Password = self.conf.teleadress_client_password
        person_search._UserId = self.conf.teleadress_client_user

        # Set what parameter to search with
        person_search.QueryParams.FindSSNo = national_identity_number

        # Set the columns to get back from search. (Only need the mobile numbers)
        person_search.QueryColumns._Mobiles = "1"

        record = self._search(person_search)
        if record is None:
            return []

        mobile_numbers = []
        for r in record:
            mobile_numbers.append(r.Mobiles)

        return mobile_numbers

    def _search_by_mobile(self, mobile_number: str) -> str | None:
        person_search = self._get_find_person()

        # Set the eduid user id and password
        person_search._Password = self.conf.teleadress_client_password
        person_search._UserId = self.conf.teleadress_client_user

        # Set what parameter to search with
        person_search.QueryParams.FindTelephone = mobile_number

        # Set the columns to get back from search. (Only need the SSNo)
        person_search.QueryColumns._SSNo = "1"

        record = self._search(person_search)

        if record is None:
            self.logger.debug(f"Got no search result on mobile number: {mobile_number}")
            return None

        return record[0].SSNo
