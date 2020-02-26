# -*- coding: utf-8 -*-
import enum
import logging
from typing import Union, List

from neo4j import Transaction
from neo4j.exceptions import ClientError, CypherError

from eduid_groupdb import BaseGraphDB, Group, User

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class GroupDB(BaseGraphDB):

    @enum.unique
    class Role(enum.Enum):
        # Role to relationship type
        MEMBER = 'IN'
        OWNER = 'OWNS'

    def db_setup(self):
        with self.db.driver.session() as session:
            # Constraints for Group nodes
            session.run('CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.scope)')
            session.run('CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.identifier)')
            session.run('CREATE CONSTRAINT ON (n:Group) ASSERT (n.scope, n.identifier) IS NODE KEY')
            # Constraints for User nodes
            session.run('CREATE CONSTRAINT ON (n:User) ASSERT exists(n.identifier)')
            session.run('CREATE CONSTRAINT ON (n:User) ASSERT n.identifier IS UNIQUE')
        logger.debug(f'{self} setup done.')

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

    def _add_or_update_users_and_groups(self, tx: Transaction, group: Group) -> None:
        for user_member in group.user_members:
            self._add_user_to_group(tx, group=group, member=user_member, role=self.Role.MEMBER)
        for group_member in group.group_members:
            self._add_group_to_group(tx, group=group, member=group_member, role=self.Role.MEMBER)
        for user_owner in group.owners:
            self._add_user_to_group(tx, group=group, member=user_owner, role=self.Role.OWNER)

    @staticmethod
    def _add_group_to_group(tx, group: Group, member: Group, role: Role):
        q = f"""
            MATCH (g:Group {{scope: $group_scope, identifier: $group_identifier}})
            MERGE (n:Group {{scope: $scope, identifier: $identifier}})-[r:{role.value}]->(g)
                ON CREATE SET
                    n.created_ts = timestamp(),
                    n.display_name = $display_name,
                    n.description = $description,
                    r.created_ts = timestamp()
                ON MATCH SET r.modified_ts = timestamp()
            SET r.display_name = $display_name
            """
        tx.run(q, group_scope=group.scope, group_identifier=group.identifier, identifier=member.identifier,
               scope=member.scope, display_name=member.display_name, description=member.description)

    @staticmethod
    def _add_user_to_group(tx, group: Group, member: User, role: Role) -> None:
        q = f"""
            MATCH (g:Group {{scope: $scope, identifier: $group_identifier}})
            MERGE (n:User {{identifier: $identifier}})-[r:{role.value}]->(g)
                ON CREATE SET r.created_ts = timestamp()
                ON MATCH SET r.modified_ts = timestamp()
            SET r.display_name = $display_name
            """
        tx.run(q, scope=group.scope, group_identifier=group.identifier, identifier=member.identifier,
               display_name=member.display_name)

    def _get_users_and_groups_by_role(self, scope: str, identifier: str, role: Role) -> List[Union[User, Group]]:
        res: List[Union[User, Group]] = []
        q = f"""
            MATCH (g: Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(m)
            RETURN r.display_name as display_name, r.created_ts as created_ts, r.modified_ts as modified_ts,
                   m.identifier as identifier, m.scope as scope, m.description as description, labels(m) as labels
            """
        with self.db.driver.session() as session:
            for record in session.run(q, scope=scope, identifier=identifier):
                labels = record.get('labels', [])
                if 'User' in labels:
                    res.append(User.from_mapping(record.data()))
                elif 'Group' in labels:
                    res.append(Group.from_mapping(record.data()))
        return res

    def get_group(self, scope: str, identifier: str) -> Group:
        q = """
            MATCH (g: Group {scope: $scope, identifier: $identifier})
            RETURN g as group
            """
        with self.db.driver.session() as session:
            group_node = session.run(q, scope=scope, identifier=identifier).single().value()
        group_data = dict(group_node.items())
        group_data['members'] = self._get_users_and_groups_by_role(scope=scope, identifier=identifier,
                                                                   role=self.Role.MEMBER)
        group_data['owners'] = self._get_users_and_groups_by_role(scope=scope, identifier=identifier,
                                                                  role=self.Role.OWNER)
        group = Group.from_mapping(group_data)
        return group

    def get_groups_for_user(self, user: User) -> List[Group]:
        q = """
            MATCH (User {identifier: $identifier})-[IN]->(g: Group)
            RETURN g as group
            """
        res: List[Group] = []
        with self.db.driver.session() as session:
            for record in session.run(q, identifier=user.identifier):
                res.append(Group.from_mapping(record.data()['group']))
        return res

    def save(self, group: Group) -> None:
        with self.db.driver.session() as session:
            try:
                tx = session.begin_transaction()
                self._create_or_update_group(tx, group)
                self._add_or_update_users_and_groups(tx, group)
                tx.success = True
            except (ClientError, CypherError) as e:
                logger.error(e)
            finally:
                # If tx.success is not explicitly set to True close will perform a rollback
                tx.close()
