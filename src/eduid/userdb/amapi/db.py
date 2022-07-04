from typing import Any, List, Mapping, Optional, Tuple, Type

from eduid.userdb import User, UserDB


class AMApiDB(UserDB[User]):
    def __init__(self, db_uri: str, db_name: str = 'eduid_am', collection: str = 'attributes'):
        super().__init__(db_uri, db_name, collection=collection)

    def get_eppn_samples(self, exclude_process_id: str, sample_size: int) -> List[str]:
        pipeline = [{"$match": {"process_id": {"nq": exclude_process_id}}}, {"$sample": {"size": sample_size}}]
        docs = self._coll.aggregate(pipeline)
        return [doc['eduPersonPrincipleName'] for doc in docs if 'eduPersonPrincipleName' in doc]
