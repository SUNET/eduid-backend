from suds.client import Client
from eduid_lookup_mobile import log
from eduid_lookup_mobile import config
from suds.plugin import MessagePlugin
from eduid_lookup_mobile.utilities import format_NIN, format_mobile_number
from eduid_lookup_mobile.development.development_search_result import _get_devel_search_result

class LogPlugin(MessagePlugin):

    def sending(self, context):
        print(str(context.envelope))

    def received(self, context):
        print(str(context.reply))


class MobileLookupClient:
    DEFAULT_CLIENT_URL = 'http://api.teleadress.se/WSDL/nnapiwebservice.wsdl'
    DEFAULT_CLIENT_PORT = 'NNAPIWebServiceSoap'
    DEFAULT_CLIENT_PERSON_CLASS = 'ns7:FindPersonClass'

    def __init__(self):

        #self.client = Client(self.DEFAULT_CLIENT_URL, plugins=[LogPlugin()])
        self.client = Client(self.DEFAULT_CLIENT_URL)
        self.client.set_options(port=self.DEFAULT_CLIENT_PORT)

        self.conf = config.read_configuration()
        self.DEFAULT_CLIENT_PASSWORD = unicode(self.conf['TELEADRESS_CLIENT_PASSWORD'])
        self.DEFAULT_CLIENT_USER = unicode(self.conf['TELEADRESS_CLIENT_USER'])

    def find_mobiles_by_NIN(self, national_identity_number, number_region=None):
        national_identity_number = format_NIN(national_identity_number)
        person_information = self._search_by_SSNo(national_identity_number)

        if not person_information or person_information['Mobiles'] is None:
            log.debug("Did not get search result from nin: {nin}".format(nin=national_identity_number))
            return []

        person_information['Mobiles'] = format_mobile_number(person_information['Mobiles'], number_region)
        return person_information['Mobiles']

    def find_NIN_by_mobile(self, mobile_number):
        person_information = self._search_by_mobile(mobile_number)
        if not person_information or person_information['nin'] is None:
            log.debug("Did not get search result from mobile number: {m_number}".format(m_number=mobile_number))
            return

        found_nin = format_NIN(person_information['nin'])
        return found_nin

    def _search(self, param):
        # Start the search
        if self.conf.get('DEVEL_MODE') == 'true':
            result = _get_devel_search_result(param)
        else:
            result = self.client.service.Find(param)

        if result._error_code != 0:
            log.debug("Error code: {err_code}, error message: {err_message}".format(err_code=result._error_code,
                                                                                    err_message=(result._error_text.encode('utf-8'))))
            return None

        # Check if the search got a hit
        if result.record_list[0]._num_records < 1:
            return None

        return result.record_list[0].record

    def _search_by_SSNo(self, national_identity_number):
        person_search = self.client.factory.create(self.DEFAULT_CLIENT_PERSON_CLASS)

        # Set the eduid user id and password
        person_search._Password = self.DEFAULT_CLIENT_PASSWORD
        person_search._UserId = self.DEFAULT_CLIENT_USER

        # Set what parameter to search with
        person_search.QueryParams.FindSSNo = national_identity_number

        # Set the columns to get back from search. (Only need the mobile numbers)
        person_search.QueryColumns._Mobiles = '1'

        record = self._search(person_search)
        if record is None:
            return {}

        mobile_numbers = []
        for r in record:
            mobile_numbers.append(r.Mobiles)

        return {'Mobiles': mobile_numbers}

    def _search_by_mobile(self, mobile_number):
        person_search = self.client.factory.create(self.DEFAULT_CLIENT_PERSON_CLASS)

        # Set the eduid user id and password
        person_search._Password = self.DEFAULT_CLIENT_PASSWORD
        person_search._UserId = self.DEFAULT_CLIENT_USER

        # Set what parameter to search with
        person_search.QueryParams.FindTelephone = mobile_number

        # Set the columns to get back from search. (Only need the SSNo)
        person_search.QueryColumns._SSNo = '1'

        record = self._search(person_search)

        if record is None:
            log.debug("Got no search result on mobile number: {m_number}".format(m_number=mobile_number))
            return {}

        return {'nin': record[0].SSNo}