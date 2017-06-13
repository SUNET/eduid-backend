# Helper code for tools accessing the raw userdb - things like database fixup scripts.

import os
import sys
import bson
import time
import pprint
import datetime

import bson.json_util

from pymongo import MongoClient, ReadPreference
from pymongo.errors import PyMongoError
from six import string_types
from copy import deepcopy


class RawDb(object):
    """
    Kind-of raw access to mongodb documents, for use in database fix/migration scripts.

    The main idea is to have an easy to initialise way to find documents, make changes
    to them (in the calling code, not in this module) and write them back to the database
    *with backups* of the data before and after modification, and an easily searchable
    log detailing all the changes.
    """
    def __init__(self, myname=None, backupbase='/root/raw_db_changes'):
        self._client = get_client()
        self._start_time = datetime.datetime.fromtimestamp(int(time.time())).isoformat(sep = '_')
        self._myname = myname
        self._backupbase = backupbase
        self._file_num = 0

    def find(self, db, collection, search_filter):
        """
        Look for documents matching search_filter in the specified database and collection.

        Returns a list of RawData instances, that can be modified and saved using the
        save_with_backup function.

        :param db: Database name
        :param collection: Collection name
        :param search_filter: PyMongo search filter

        :type db: string_types
        :type collection: string_types

        :rtype: Generator[RawData]
        """
        try:
            for doc in self._client[db][collection].find(search_filter):
                yield RawData(doc, db, collection)
        except PyMongoError as exc:
            sys.stderr.write('{}\n\nFailed reading from mongodb ({}.{}) - '
                             'try sourcing the file /root/.mongo_credentials first?\n'.format(exc, db, collection))
            sys.exit(1)

    def save_with_backup(self, raw, dry_run=True):
        """
        Save a mongodb document while trying to carefully make a backup of the document before, after and what changed.
        """
        if not self._myname:
            sys.stderr.write("Can't save with backup unless RawDb is initialized with myname\n")
            sys.exit(1)

        if not os.path.isdir(self._backupbase):
            sys.stderr.write('\n\nBackup basedir {} not found, '
                             'running in a container without the volume mounted?\n'.format(self._backupbase))
            sys.exit(1)

        if 'eduPersonPrincipalName' in raw.doc:
            _id = raw.doc['eduPersonPrincipalName']
            if raw.doc['eduPersonPrincipalName'] != raw.before.get('eduPersonPrincipalName'):
                sys.stderr.write('REFUSING to update eduPersonPrincipalName ({} -> {})'.format(
                    raw.before.get('eduPersonPrincipalName'), raw.doc['eduPersonPrincipalName']))
                sys.exit(1)
        else:
            _id = '{}'.format(raw.doc['_id'])

        if raw.doc['_id'] != raw.before['_id']:
            sys.stderr.write('REFUSING to update _id ({} -> {})'.format(raw.before['_id'], raw.doc['_id']))
            sys.exit(1)

        dbcoll = '{}.{}'.format(raw.db, raw.collection)

        if raw.before == raw.doc:
            sys.stderr.write("Document in {} with id {} not changed, aborting save_with_backup\n".format(dbcoll, _id))
            return

        self._file_num = 0
        backup_dir = self._make_backupdir(dbcoll, _id)
        self._write_before_and_after(raw, backup_dir)

        if dry_run:
            res = 'DRY_RUN'
        else:
            res = self._client[raw.db][raw.collection].update({'_id': raw.doc['_id']}, raw.doc)

        # Write changes.txt after saving, so it will also indicate a successful save
        self._write_changes(raw, backup_dir, res)

    def _write_changes(self, raw, backup_dir, res):
        """
        Write a file with one line per change between the before-doc and current doc.
        The format is intended to be easy to grep through.
        """
        filename = self._get_backup_filename(backup_dir, 'changes', 'txt')
        with open(filename, 'w') as fd:
            for k in sorted(set(raw.doc) - set(raw.before)):
                fd.write('ADD: {}: {}\n'.format(k, raw.doc[k].encode('utf-8')))
            for k in sorted(set(raw.before) - set(raw.doc)):
                fd.write('DEL: {}: {}\n'.format(k, raw.before[k].encode('utf-8')))
            for k in sorted(raw.doc.keys()):
                if k not in raw.before:
                    continue
                if raw.doc[k] != raw.before[k]:
                    fd.write('MOD: {}: {} -> {}\n'.format(
                        k, raw.before[k].encode('utf-8'), raw.doc[k].encode('utf-8')))

            fd.write('UPDATE_RESULT: {}\n'.format(res))

    def _write_before_and_after(self, raw, backup_dir):
        """
        Write before- and after backup files of the document being saved, in JSON format.
        """
        filename = self._get_backup_filename(backup_dir, 'before', 'json')
        with open(filename, 'w') as fd:
            fd.write(bson.json_util.dumps(raw.before, indent=True, sort_keys=True))

        filename = self._get_backup_filename(backup_dir, 'after', 'json')
        with open(filename, 'w') as fd:
            fd.write(bson.json_util.dumps(raw.doc, indent=True, sort_keys=True))

    def _get_backup_filename(self, dirname, filename, ext):
        """
        Look for a backup filename that hasn't been used. The use of self._file_num
        should mean we get matching before- after- and changes sets.
        """
        while True:
            if self._file_num == 0:
                fn = filename + '.' + ext
            else:
                fn = '{}_{}.{}'.format(filename, self._file_num, ext)
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
            sys.stderr.write('\n\nBackup basedir {} not found, running in a container '
                             'without the volume mounted?\n'.format(self._backupbase))
            sys.exit(1)

        backup_dir = os.path.join(self._backupbase, self._myname, self._start_time, dbcoll, _id)
        os.makedirs(backup_dir)

        return backup_dir


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
            if isinstance(value, string_types):
                res.extend(['  {!s:>25}: {!s}'.format(key, value.encode('utf-8'))])
            elif isinstance(value, datetime.datetime):
                res.extend(['  {!s:>25}: {!s}'.format(key, value.isoformat())])
            else:
                # pprint.pformat unknown data, and increase the indentation
                pretty = pprint.pformat(value).replace('\n  ', '\n' + (' ' * 29))
                print("  {!s:>25}: {}".format(key, pretty))
        return res


def get_client():
    """
    You should probably get an instance of RawDb instead of using this function.

    :return: A MongoClient instance
    :rtype: MongoClient
    """
    user = os.environ.get('MONGODB_ADMIN')
    pw = os.environ.get('MONGODB_ADMIN_PASSWORD')
    if user and pw:
        dburi = 'mongodb://{!s}:{!s}@localhost:27017/'.format(user, pw)
    else:
        dburi = 'mongodb://localhost:27017/'

    return MongoClient(dburi, read_preference=ReadPreference.SECONDARY)
