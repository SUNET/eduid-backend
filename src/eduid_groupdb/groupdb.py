# -*- coding: utf-8 -*-
from enum import Enum
from typing import Union
from neo4j import Transaction
from neo4j.exceptions import ClientError, CypherError
from eduid_groupdb import BaseGraphDB, Group, User
from eduid_groupdb.exceptions import UnsupportedMemberType
import logging

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class GroupDB(BaseGraphDB):

    def db_setup(self):
        with self.db.driver.session() as session:
            # Constraints for Group nodes
            session.run('CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.scope)')
            session.run('CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.identifier)')
            session.run('CREATE CONSTRAINT ON (n:Group) ASSERT (n.scope, n.identifier) IS NODE KEY')
            # Constraints for User nodes
            session.run('CREATE CONSTRAINT ON (n:User) ASSERT exists(n.identifier)')
            session.run('CREATE CONSTRAINT ON (n:User) ASSERT n.identifier IS UNIQUE')
            # Constraints for IN relationships
            session.run('CREATE CONSTRAINT ON ()-[r:IN]-() ASSERT exists(r.role)')

    @staticmethod
    def _create_or_update_group(tx: Transaction, group: Group) -> None:
        q = """
            MERGE (n:Group {scope: $scope, identifier: $identifier})
                ON CREATE SET n.created_ts = timestamp()
                ON MATCH SET n.modified_ts = timestamp()
            SET n.display_name = $display_name
            SET n.description = $description            
            """
        tx.run(q, scope=group.scope, identifier=group.identifier, display_name=group.display_name,
               description=group.description)

    def _add_or_update_members(self, tx: Transaction, group: Group) -> None:
        for member in group.members:
            if isinstance(member, User):
                self._add_user_to_group(tx, group=group, member=member)
            elif isinstance(member, Group):
                self._add_group_to_group(tx, group=group, member=member)
            else:
                raise UnsupportedMemberType(f'Type {type(member)} not supported as group member')

    def _add_group_to_group(self, tx, group: Group, member: Group):
        pass

    @staticmethod
    def _add_user_to_group(tx, group: Group, member: User) -> None:
        q = """
            MATCH (g:Group {scope: $scope, identifier: $group_identifier})
            MERGE (n:User {identifier: $identifier})-[r:IN]->(g)
                ON CREATE SET r.created_ts = timestamp()
                ON MATCH SET r.modified_ts = timestamp()
            SET r.role = $role
            SET r.display_name = $display_name
            """
        tx.run(q, identifier=member.identifier, scope=group.scope, group_identifier=group.identifier,
               role=member.role.value, display_name=member.display_name)

    def get_group(self, scope: str, identifier: str) -> Group:
        q = """
            MATCH (n: Group {scope: $scope, identifier: $identifier})                       
            RETURN n
            """
        with self.db.driver.session() as session:
            group_node = session.run(q, scope=scope, identifier=identifier).single().value()
            print(group_node)

        q = """
            OPTIONAL MATCH (n: Group {scope: $scope, identifier: $identifier})<-[r:IN]-(m)             
            RETURN r.role as role, r.display_name as display_name, r.created_ts as created_ts,
                r.modified_ts as modified_ts, m.identifier as identifier
            """
        with self.db.driver.session() as session:
            for record in session.run(q, scope=scope, identifier=identifier):
                print(User.from_dict(record.data()))

    def save(self, group: Group) -> None:
        with self.db.driver.session() as session:
            try:
                tx = session.begin_transaction()
                self._create_or_update_group(tx, group)
                self._add_or_update_members(tx, group)
                tx.success = True
            except (ClientError, CypherError, UnsupportedMemberType) as e:
                logger.error(e)
            finally:
                # If tx.success is not explicitly set to True close will perform a rollback
                tx.close()
