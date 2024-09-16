# Helper code for tools accessing the raw userdb - things like database fixup scripts.
from __future__ import annotations

import argparse
import datetime
import os
import pprint
import sys
import time
from collections.abc import Generator
from copy import deepcopy
from typing import Any

import bson
import bson.json_util
from pymongo import MongoClient, ReadPreference
from pymongo.errors import PyMongoError

from eduid.userdb.db import TUserDbDocument

volunteers = {
    "ft:staging": "vofaz-tajod",
    "ft:prod": "takaj-sosup",
    "lundberg:staging": "tovuk-zizih",
    "lundberg:prod": "rubom-lujov",
    "john:staging": "faraf-livok",
    "john:prod": "hofij-zanok",
}
usual_suspects = volunteers.values()

# TODO: remove PYTHON_UUID_LEGACY_JSON_OPTIONS when we switch uuidRepresentation to "standard"
PYTHON_UUID_LEGACY_JSON_OPTIONS: bson.json_util.JSONOptions = bson.json_util.JSONOptions(
    json_mode=bson.json_util.JSONMode.RELAXED, uuid_representation=bson.binary.UuidRepresentation.PYTHON_LEGACY
)


class RawDb:
    """
    Kind-of raw access to mongodb documents, for use in database fix/migration scripts.

    The main idea is to have an easy to initialise way to find documents, make changes
    to them (in the calling code, not in this module) and write them back to the database
    *with backups* of the data before and after modification, and an easily searchable
    log detailing all the changes.
    """

    def __init__(self, myname: str | None = None, backupbase: str = "/root/raw_db_changes"):
        self._client = get_client()
        self._start_time: str = datetime.datetime.fromtimestamp(int(time.time())).isoformat(sep="_").replace(":", "")
        self._myname: str | None = myname
        self._backupbase: str = backupbase
        self._file_num: int = 0

    def find(self, db: str, collection: str, search_filter: Any) -> Generator[RawData, None, None]:
        """
        Look for documents matching search_filter in the specified database and collection.

        Returns a list of RawData instances, that can be modified and saved using the
        save_with_backup function.

        :param db: Database name
        :param collection: Collection name
        :param search_filter: PyMongo search filter
        """
        try:
            for doc in self._client[db][collection].find(search_filter):
                yield RawData(doc, db, collection)
        except PyMongoError as exc:
            sys.stderr.write(
                f"{exc}\n\nFailed reading from mongodb ({db}.{collection}) - "
                "try sourcing the file /root/.mongo_credentials first?\n"
            )
            sys.exit(1)

    def save_with_backup(self, raw: RawData, dry_run: bool = True) -> Any:
        """
        Save a mongodb document while trying to carefully make a backup of the document before, after and what changed.

        If raw.doc has the key 'DELETE_DOCUMENT' set to True, it will be removed from the database.
        """
        if not self._myname:
            sys.stderr.write("Can't save with backup unless RawDb is initialized with myname\n")
            sys.exit(1)

        if not os.path.isdir(self._backupbase):
            sys.stderr.write(
                f"\n\nBackup basedir {self._backupbase} not found, "
                "running in a container without the volume mounted?\n"
            )
            sys.exit(1)

        if raw.doc["_id"] != raw.before["_id"]:
            sys.stderr.write("REFUSING to update _id ({} -> {})\n".format(raw.before["_id"], raw.doc["_id"]))
            sys.exit(1)

        _id = "{}".format(raw.doc["_id"])
        if "eduPersonPrincipalName" in raw.before:
            _id = raw.before["eduPersonPrincipalName"]

        if raw.doc.get("DELETE_DOCUMENT") is True:
            raw.doc = TUserDbDocument({})
        else:
            if "eduPersonPrincipalName" in raw.doc or "eduPersonPrincipalName" in raw.before:
                if raw.doc.get("eduPersonPrincipalName") != raw.before.get("eduPersonPrincipalName"):
                    sys.stderr.write(
                        "REFUSING to update eduPersonPrincipalName ({} -> {})".format(
                            raw.before.get("eduPersonPrincipalName"), raw.doc.get("eduPersonPrincipalName")
                        )
                    )
                    sys.exit(1)

        db_coll = f"{raw.db}.{raw.collection}"

        if raw.before == raw.doc:
            sys.stderr.write(f"Document in {db_coll} with id {_id} not changed, aborting save_with_backup\n")
            return

        self._file_num = 0
        backup_dir = self._make_backupdir(db_coll, _id)
        self._write_before_and_after(raw, backup_dir)

        if dry_run:
            res = "DRY_RUN"
        else:
            if len(raw.doc):
                replace_res = self._client[raw.db][raw.collection].replace_one({"_id": raw.doc["_id"]}, raw.doc)
                res = f"UPDATE {replace_res}"
            else:
                delete_res = self._client[raw.db][raw.collection].delete_one({"_id": raw.before["_id"]})
                res = f"REMOVE {delete_res}"

        # Write changes.txt after saving, so it will also indicate a successful save
        return self._write_changes(raw, backup_dir, res)

    def _write_changes(self, raw: RawData, backup_dir: str, res: Any) -> Any:
        """
        Write a file with one line per change between the before-doc and current doc.
        The format is intended to be easy to grep through.
        """

        def safe_encode(k2: Any, v2: Any) -> str:
            try:
                return bson.json_util.dumps({k2: v2}, json_options=PYTHON_UUID_LEGACY_JSON_OPTIONS)
            except:
                sys.stderr.write(f"Failed encoding key {k2!r}: {v2!r}\n\n")
                raise

        filename = self._get_backup_filename(backup_dir, "changes", "txt")
        with open(filename, "w") as fd:
            for k in sorted(set(raw.doc) - set(raw.before)):
                fd.write(f"ADD: {safe_encode(k, raw.doc[k])}\n")
            for k in sorted(set(raw.before) - set(raw.doc)):
                fd.write(f"DEL: {safe_encode(k, raw.before[k])}\n")
            for k in sorted(raw.doc.keys()):
                if k not in raw.before:
                    continue
                if raw.doc[k] != raw.before[k]:
                    fd.write(f"MOD: BEFORE={safe_encode(k, raw.before[k])} AFTER={safe_encode(k, raw.doc[k])}\n")

            fd.write(f"DB_RESULT: {res}\n")
        return res

    def _write_before_and_after(self, raw: RawData, backup_dir: str):
        """
        Write before- and after backup files of the document being saved, in JSON format.
        """
        filename = self._get_backup_filename(backup_dir, "before", "json")
        with open(filename, "w") as fd:
            fd.write(
                bson.json_util.dumps(
                    raw.before, indent=True, sort_keys=True, json_options=PYTHON_UUID_LEGACY_JSON_OPTIONS
                )
                + "\n"
            )

        filename = self._get_backup_filename(backup_dir, "after", "json")
        with open(filename, "w") as fd:
            fd.write(
                bson.json_util.dumps(raw.doc, indent=True, sort_keys=True, json_options=PYTHON_UUID_LEGACY_JSON_OPTIONS)
                + "\n"
            )

    def _get_backup_filename(self, dirname: str, filename: str, ext: str):
        """
        Look for a backup filename that hasn't been used. The use of self._file_num
        should mean we get matching before- after- and changes sets.
        """
        while True:
            if self._file_num == 0:
                fn = filename + "." + ext
            else:
                fn = f"{filename}_{self._file_num}.{ext}"
            full_fn = os.path.join(dirname, fn)
            if os.path.isfile(full_fn):
                self._file_num += 1
            else:
                return full_fn

    def _make_backupdir(self, db_coll: str, _id: str) -> str:
        if not self._myname:
            sys.stderr.write("Can't save with backup unless RawDb is initialized with myname\n")
            sys.exit(1)

        if not os.path.isdir(self._backupbase):
            sys.stderr.write(
                f"\n\nBackup basedir {self._backupbase} not found, running in a container "
                "without the volume mounted?\n"
            )
            sys.exit(1)

        backup_dir = os.path.join(self.backupdir, db_coll, _id)
        os.makedirs(backup_dir)

        return backup_dir

    @property
    def backupdir(self) -> str:
        """
        The top level path for data logs created by the current run of a db fix script.
        :return: Directory name
        """
        if not self._myname:
            sys.stderr.write("Can't save with backup unless RawDb is initialized with myname\n")
            sys.exit(1)
        return os.path.join(self._backupbase, self._myname, self._start_time)


class RawData:
    """
    Holder of raw data read from the database.

    Preserves the original data so that it can be backed up in case updates are saved
    using db.save_with_backup() above.

    :param doc: Mongo document
    :param db: Name of database
    :param collection: Name of collection
    """

    def __init__(self, doc: TUserDbDocument, db: str, collection: str):
        self._before = deepcopy(doc)
        self._db = db
        self._collection = collection
        self.doc = doc

    #
    # read-only attributes
    #
    @property
    def before(self) -> TUserDbDocument:
        """
        :return: The original document as read from mongodb
        """
        return self._before

    @property
    def db(self) -> str:
        """
        :return: Database name
        """
        return self._db

    @property
    def collection(self) -> str:
        """
        :return: Collection name
        """
        return self._collection

    def pretty(self) -> list[str]:
        """
        Format for simple pretty-printing as key: value pairs.
        """
        res: list[str] = []
        for key, value in self.doc.items():
            if isinstance(value, str):
                res.extend(["  {!s:>25}: {!s}".format(key, value.encode("utf-8"))])
            elif isinstance(value, datetime.datetime):
                res.extend([f"  {key!s:>25}: {value.isoformat()!s}"])
            else:
                # pprint.pformat unknown data, and increase the indentation
                pretty = pprint.pformat(value).replace("\n  ", "\n" + (" " * 29))
                print(f"  {key!s:>25}: {pretty}")
        return res


def get_client() -> MongoClient[TUserDbDocument]:
    """
    You should probably get an instance of RawDb instead of using this function.

    :return: A MongoClient instance
    """
    user = os.environ.get("MONGODB_ADMIN")
    pw = os.environ.get("MONGODB_ADMIN_PASSWORD")
    host = os.environ.get("MONGODB_HOST")
    port = os.environ.get("MONGODB_PORT")
    if not host:
        host = "localhost"
    if not port:
        port = "27017"
    if user and pw:
        db_uri = f"mongodb://{user}:{pw}@{host}:{port}/"
    else:
        db_uri = f"mongodb://{host}:{port}/"

    return MongoClient[TUserDbDocument](
        db_uri,
        read_preference=ReadPreference.SECONDARY_PREFERRED,
        # TODO: switch uuidRepresentation to "standard" when we made sure all UUIDs are stored as strings
        uuidRepresentation="pythonLegacy",
    )


def get_argparser(description: str | None = None, eppn: bool = False) -> argparse.ArgumentParser:
    """
    Get a standard argparser for raw db scripts.

    In order to allow the caller to add more arguments, the caller must call parser.parse_args().

    :param description: Script description
    :param eppn: If True, add a positional argument for a single eppn.
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Enable debug operation")
    parser.add_argument(
        "--force", dest="force", action="store_true", default=False, help="Actually make changes in the database"
    )

    if eppn is True:
        parser.add_argument("eppn", metavar="EPPN", type=str, help="eduPersonPrincipalName to operate on")

    return parser
