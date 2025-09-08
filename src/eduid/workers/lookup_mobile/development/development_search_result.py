__author__ = "mathiashedstrom"

from suds.sudsobject import Object

from eduid.workers.lookup_mobile.development import nin_mobile_db


class DevelopResult:
    class Record:
        def __init__(self, nin: str | None, mobile: str) -> None:
            self.SSNo = nin
            self.Mobiles = mobile

    class RecordList:
        def __init__(self) -> None:
            self._num_records = 0
            self.record: list[DevelopResult.Record] = []

        def append_record(self, record: "DevelopResult.Record") -> None:
            self.record.append(record)
            self._num_records = len(self.record)

    def __init__(self) -> None:
        self.record_list = [DevelopResult.RecordList()]
        self._error_code = 0
        self._error_text = ""


def _get_devel_search_result(search_param: Object) -> DevelopResult:
    nin = search_param.QueryParams.FindSSNo
    mobile = search_param.QueryParams.FindTelephone

    result = DevelopResult()

    if nin is not None:
        mobile = nin_mobile_db.get_mobile(nin)
        for one_number in mobile:
            result.record_list[0].append_record(DevelopResult.Record(nin, one_number))
    elif mobile is not None:
        nin = nin_mobile_db.get_nin(mobile)
        result.record_list[0].append_record(DevelopResult.Record(nin, mobile))

    return result
