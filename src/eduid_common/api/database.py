# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import current_app

from eduid_userdb.userdb import UserDB
from eduid_userdb.proofing.proofingdb import LetterProofingStateDB

__author__ = 'lundberg'


class ApiDatabase(object):

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.config.setdefault('MONGO_URI', 'mongodb://')
        app.teardown_appcontext(self.teardown)
        app.extensions.setdefault(self.__class__.__name__, {})

    def teardown(self, exception):
        pass  # What to do here?
        #app = self.app or current_app
        #ctx = app.extensions[self.__class__.__name__]
        #for db_name in ctx.keys():
        #    db = ctx.get(db_name, None)
        #    if db is not None:
        #        current_app.logger.debug('{} closed'.format(db))
        #        db.close()

    def get_db(self, db_name, db_cls, collection=None):
        """
        :param db_name: Unique db name for current app
        :type db_name: str
        :param db_cls: Db class from eduid_userdb
        :type db_cls: Db class
        :param collection: Mongo collection
        :type collection: str | None
        :return: Db instance from eduid_userdb
        :rtype: Db object
        """
        app = self.app or current_app
        mongo_uri = current_app.config['MONGO_URI']
        ctx = app.extensions[self.__class__.__name__]
        db = ctx.get(db_name, None)
        if db is None:
            if collection is None:
                db = db_cls(mongo_uri)
            else:
                db = db_cls(mongo_uri, collection)
            current_app.logger.debug('{} initialized'.format(db))
            ctx[db_name] = db
        return db

    @property
    def userdb(self):
        """
        :return: UserDB object
        :rtype: UserDB
        """
        return self.get_db('_userdb', UserDB, 'eduid_am')

    @property
    def letter_proofing_statedb(self):
        """
        :return: LetterNinProofingUserDB object
        :rtype: LetterNinProofingUserDB
        """
        return self.get_db('_letterproofingstatedb', LetterProofingStateDB)







