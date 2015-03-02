from suds.client import Client
from eduid_lookup_mobile import log
from eduid_lookup_mobile import config
from suds.plugin import MessagePlugin
from eduid_lookup_mobile.utilities import format_NIN, format_mobile_number

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

        conf = config.read_configuration()
        self.DEFAULT_CLIENT_PASSWORD = unicode(conf['TELEADRESS_CLIENT_PASSWORD'])
        self.DEFAULT_CLIENT_USER = unicode(conf['TELEADRESS_CLIENT_USER'])

    def verify_identity(self, national_identity_number, mobile_number_list):
        result = {'success': False, 'status': 'bad_input', 'mobile': None}
        if national_identity_number is None or mobile_number_list is None:
            return result

        national_identity_number = format_NIN(national_identity_number)
        status = 'no_phone'
        valid_mobile = None

        for mobile_number in mobile_number_list:
            status = 'no_match'
            nin_mobile = self.find_NIN_by_mobile(mobile_number)
            nin_mobile = format_NIN(nin_mobile)

            if nin_mobile == national_identity_number:
                valid_mobile = mobile_number
                status = 'match'
                break
            elif nin_mobile is not None:
                # TODO check navet relatives
                status = 'match_by_navet'

        result = {'success': valid_mobile is not None, 'status': status, 'mobile': valid_mobile}

        log.info("Validation result:: success:{success}, status:{status}, mobile number used:{mobile_number}".format(
            success=result['success'], status=result['status'], mobile_number=result['mobile']))

        return result

    def find_mobiles_by_NIN(self, national_identity_number, number_region=None):
        national_identity_number = format_NIN(national_identity_number)
        person_information = self._search_by_SSNo(national_identity_number)
        person_information['Mobiles'] = format_mobile_number(person_information['Mobiles'], number_region)
        return person_information

    def find_NIN_by_mobile(self, mobile_number):
        person_information = self._search_by_mobile(mobile_number)
        if not person_information or person_information['nin'] is None:
            log.debug("Did not get search result from mobile number: {m_number}".format(m_number=mobile_number))
            return

        found_nin = format_NIN(person_information['nin'])
        return found_nin

    def _search(self, param):
        # Start the search
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
            log.debug("Got no search result on NIN: {nin}".format(nin=national_identity_number))
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