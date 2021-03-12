from typing import Dict, List, Optional

from suds.client import Client

from eduid.common.config.workers import MobConfig
from eduid.workers.lookup_mobile.decorators import TransactionAudit
from eduid.workers.lookup_mobile.development.development_search_result import _get_devel_search_result
from eduid.workers.lookup_mobile.utilities import format_mobile_number, format_NIN

DEFAULT_CLIENT_URL = 'http://api.teleadress.se/WSDL/nnapiwebservice.wsdl'
DEFAULT_CLIENT_PORT = 'NNAPIWebServiceSoap'
DEFAULT_CLIENT_PERSON_CLASS = 'ns7:FindPersonClass'


class MobileLookupClient(object):
    def __init__(self, logger, config: MobConfig) -> None:
        self.conf = config

        # enable transaction logging if configured
        self.transaction_audit = self.conf.transaction_audit and self.conf.mongo_uri

        self.client = Client(DEFAULT_CLIENT_URL)
        self.client.set_options(port=DEFAULT_CLIENT_PORT)
        self.logger = logger

        self.DEFAULT_CLIENT_PASSWORD = str(self.conf.teleadress_client_password)
        self.DEFAULT_CLIENT_USER = str(self.conf.teleadress_client_user)

    @TransactionAudit()
    def find_mobiles_by_NIN(self, national_identity_number: str, number_region=None) -> List[str]:
        formatted_nin = format_NIN(national_identity_number)
        if not formatted_nin:
            self.logger.error(f'Invalid NIN input: {national_identity_number}')
            return []

        mobiles = self._search_by_SSNo(formatted_nin)

        if not mobiles:
            self.logger.debug(f'Did not get search result from nin: {formatted_nin}')
            return []

        return format_mobile_number(mobiles, number_region)

    @TransactionAudit()
    def find_NIN_by_mobile(self, mobile_number) -> Optional[str]:
        nin = self._search_by_mobile(mobile_number)
        if not nin:
            self.logger.debug(f'Did not get search result from mobile number: {mobile_number}')
            return None

        return format_NIN(nin)

    def _search(self, param):
        # Start the search
        if self.conf.devel_mode is True:
            result = _get_devel_search_result(param)
        else:
            result = self.client.service.Find(param)

        if result._error_code != 0:
            self.logger.debug(
                "Error code: {err_code}, error message: {err_message}".format(
                    err_code=result._error_code, err_message=(result._error_text.encode('utf-8'))
                )
            )
            return None

        # Check if the search got a hit
        if result.record_list[0]._num_records < 1:
            return None

        return result.record_list[0].record

    def _search_by_SSNo(self, national_identity_number: str) -> List[str]:
        person_search = self.client.factory.create(DEFAULT_CLIENT_PERSON_CLASS)

        # Set the eduid user id and password
        person_search._Password = self.DEFAULT_CLIENT_PASSWORD
        person_search._UserId = self.DEFAULT_CLIENT_USER

        # Set what parameter to search with
        person_search.QueryParams.FindSSNo = national_identity_number

        # Set the columns to get back from search. (Only need the mobile numbers)
        person_search.QueryColumns._Mobiles = '1'

        record = self._search(person_search)
        if record is None:
            return []

        mobile_numbers = []
        for r in record:
            mobile_numbers.append(r.Mobiles)

        return mobile_numbers

    def _search_by_mobile(self, mobile_number: str) -> Optional[str]:
        person_search = self.client.factory.create(DEFAULT_CLIENT_PERSON_CLASS)

        # Set the eduid user id and password
        person_search._Password = self.DEFAULT_CLIENT_PASSWORD
        person_search._UserId = self.DEFAULT_CLIENT_USER

        # Set what parameter to search with
        person_search.QueryParams.FindTelephone = mobile_number

        # Set the columns to get back from search. (Only need the SSNo)
        person_search.QueryColumns._SSNo = '1'

        record = self._search(person_search)

        if record is None:
            self.logger.debug(f"Got no search result on mobile number: {mobile_number}")
            return None

        return record[0].SSNo
