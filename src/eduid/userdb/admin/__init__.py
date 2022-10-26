# Helper code for tools accessing the raw userdb - things like database fixup scripts.
from __future__ import annotations

import argparse
import datetime
import os
import pprint
import sys
import time
from copy import deepcopy
from typing import Any, Generator

import bson
import bson.json_util
from pymongo import MongoClient, ReadPreference
from pymongo.errors import PyMongoError

volunteers = {
    "ft:staging": "vofaz-tajod",
    "ft:prod": "takaj-sosup",
    "lundberg:staging": "tovuk-zizih",
    "lundberg:prod": "rubom-lujov",
    "john:staging": "faraf-livok",
    "john:prod": "hofij-zanok",
}
usual_suspects = volunteers.values()


class RawDb(object):
    """
    Kind-of raw access to mongodb documents, for use in database fix/migration scripts.

    The main idea is to have an easy to initialise way to find documents, make changes
    to them (in the calling code, not in this module) and write them back to the database
    *with backups* of the data before and after modification, and an easily searchable
    log detailing all the changes.
    """

    def __init__(self, myname=None, backupbase="/root/raw_db_changes"):
        self._client = get_client()
        self._start_time = datetime.datetime.fromtimestamp(int(time.time())).isoformat(sep="_").replace(":", "")
        self._myname = myname
        self._backupbase = backupbase
        self._file_num = 0

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
                "{}\n\nFailed reading from mongodb ({}.{}) - "
                "try sourcing the file /root/.mongo_credentials first?\n".format(exc, db, collection)
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
                "\n\nBackup basedir {} not found, "
                "running in a container without the volume mounted?\n".format(self._backupbase)
            )
            sys.exit(1)

        if raw.doc["_id"] != raw.before["_id"]:
            sys.stderr.write("REFUSING to update _id ({} -> {})\n".format(raw.before["_id"], raw.doc["_id"]))
            sys.exit(1)

        _id = "{}".format(raw.doc["_id"])
        if "eduPersonPrincipalName" in raw.before:
            _id = raw.before["eduPersonPrincipalName"]

        if raw.doc.get("DELETE_DOCUMENT") is True:
            raw.doc = {}
        else:
            if "eduPersonPrincipalName" in raw.doc or "eduPersonPrincipalName" in raw.before:
                if raw.doc.get("eduPersonPrincipalName") != raw.before.get("eduPersonPrincipalName"):
                    sys.stderr.write(
                        "REFUSING to update eduPersonPrincipalName ({} -> {})".format(
                            raw.before.get("eduPersonPrincipalName"), raw.doc.get("eduPersonPrincipalName")
                        )
                    )
                    sys.exit(1)

        dbcoll = "{}.{}".format(raw.db, raw.collection)

        if raw.before == raw.doc:
            sys.stderr.write("Document in {} with id {} not changed, aborting save_with_backup\n".format(dbcoll, _id))
            return

        self._file_num = 0
        backup_dir = self._make_backupdir(dbcoll, _id)
        self._write_before_and_after(raw, backup_dir)

        if dry_run:
            res = "DRY_RUN"
        else:
            if len(raw.doc):
                db_res = self._client[raw.db][raw.collection].replace_one({"_id": raw.doc["_id"]}, raw.doc)
                res = f"UPDATE {db_res}"
            else:
                db_res = self._client[raw.db][raw.collection].remove({"_id": raw.before["_id"]})
                res = "REMOVE {}".format(db_res)

        # Write changes.txt after saving, so it will also indicate a successful save
        return self._write_changes(raw, backup_dir, res)

    def _write_changes(self, raw, backup_dir, res):
        """
        Write a file with one line per change between the before-doc and current doc.
        The format is intended to be easy to grep through.
        """

        def safe_encode(k2, v2):
            try:
                return bson.json_util.dumps({k2: v2})
            except:
                sys.stderr.write("Failed encoding key {!r}: {!r}\n\n".format(k2, v2))
                raise

        filename = self._get_backup_filename(backup_dir, "changes", "txt")
        with open(filename, "w") as fd:
            for k in sorted(set(raw.doc) - set(raw.before)):
                fd.write("ADD: {}\n".format(safe_encode(k, raw.doc[k])))
            for k in sorted(set(raw.before) - set(raw.doc)):
                fd.write("DEL: {}\n".format(safe_encode(k, raw.before[k])))
            for k in sorted(raw.doc.keys()):
                if k not in raw.before:
                    continue
                if raw.doc[k] != raw.before[k]:
                    fd.write(
                        "MOD: BEFORE={} AFTER={}\n".format(
                            safe_encode(k, raw.before[k]),
                            safe_encode(k, raw.doc[k]),
                        )
                    )

            fd.write("DB_RESULT: {}\n".format(res))
        return res

    def _write_before_and_after(self, raw, backup_dir):
        """
        Write before- and after backup files of the document being saved, in JSON format.
        """
        filename = self._get_backup_filename(backup_dir, "before", "json")
        with open(filename, "w") as fd:
            fd.write(bson.json_util.dumps(raw.before, indent=True, sort_keys=True) + "\n")

        filename = self._get_backup_filename(backup_dir, "after", "json")
        with open(filename, "w") as fd:
            fd.write(bson.json_util.dumps(raw.doc, indent=True, sort_keys=True) + "\n")

    def _get_backup_filename(self, dirname, filename, ext):
        """
        Look for a backup filename that hasn't been used. The use of self._file_num
        should mean we get matching before- after- and changes sets.
        """
        while True:
            if self._file_num == 0:
                fn = filename + "." + ext
            else:
                fn = "{}_{}.{}".format(filename, self._file_num, ext)
            fullfn = os.path.join(dirname, fn)
            if os.path.isfile(fullfn):
                self._file_num += 1
            else:
                return fullfn

    def _make_backupdir(self, dbcoll, _id):
        if not self._myname:
            sys.stderr.write("Can't save with backup unless RawDb is initialized with myname\n")
            sys.exit(1)

        if not os.path.isdir(self._backupbase):
            sys.stderr.write(
                "\n\nBackup basedir {} not found, running in a container "
                "without the volume mounted?\n".format(self._backupbase)
            )
            sys.exit(1)

        backup_dir = os.path.join(self.backupdir, dbcoll, _id)
        os.makedirs(backup_dir)

        return backup_dir

    @property
    def backupdir(self):
        """
        The top level path for data logs created by the current run of a db fix script.
        :return: Directory
        :rtype: string_types
        """
        return os.path.join(self._backupbase, self._myname, self._start_time)


class RawData(object):
    """
    Holder of raw data read from the database.

    Preserves the original data so that it can be backed up in case updates are saved
    using db.save_with_backup() above.

    :param doc: Mongo document
    :param db: Name of database
    :param collection: Name of collection

    :type doc: dict
    :type db: string_types
    :type collection: string_types
    """

    def __init__(self, doc, db, collection):
        self._before = deepcopy(doc)
        self._db = db
        self._collection = collection
        self.doc = doc

    #
    # read-only attributes
    #
    @property
    def before(self):
        """
        :return: The original document as read from mongodb
        :rtype: dict
        """
        return self._before

    @property
    def db(self):
        """
        :return: Database name
        :rtype: string_types
        """
        return self._db

    @property
    def collection(self):
        """
        :return: Collection name
        :rtype: string_types
        """
        return self._collection

    def pretty(self):
        """
        Format for simple pretty-printing as key: value pairs.
        :rtype: [string_types]
        """
        res = []
        for (key, value) in self.doc.items():
            if isinstance(value, str):
                res.extend(["  {!s:>25}: {!s}".format(key, value.encode("utf-8"))])
            elif isinstance(value, datetime.datetime):
                res.extend(["  {!s:>25}: {!s}".format(key, value.isoformat())])
            else:
                # pprint.pformat unknown data, and increase the indentation
                pretty = pprint.pformat(value).replace("\n  ", "\n" + (" " * 29))
                print("  {!s:>25}: {}".format(key, pretty))
        return res


def get_client():
    """
    You should probably get an instance of RawDb instead of using this function.

    :return: A MongoClient instance
    :rtype: MongoClient
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
        dburi = f"mongodb://{user}:{pw}@{host}:{port}/"
    else:
        dburi = f"mongodb://{host}:{port}/"

    return MongoClient(dburi, read_preference=ReadPreference.SECONDARY)


def get_argparser(description=None, eppn=False):
    """
    Get a standard argparser for raw db scripts.

    In order to allow the caller to add more arguments, the caller must call parser.parse_args().

    :param description: Script description
    :param eppn: If True, add a positional argument for a single eppn.
    :rtype: argparse.ArgumentParser
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--debug", dest="debug", action="store_true", default=False, help="Enable debug operation")
    parser.add_argument(
        "--force", dest="force", action="store_true", default=False, help="Actually make changes in the database"
    )

    if eppn is True:
        parser.add_argument("eppn", metavar="EPPN", type=str, help="eduPersonPrincipalName to operate on")

    return parser
