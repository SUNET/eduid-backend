# -*- coding: utf-8 -*-
import enum
import logging
from typing import Union, List, Optional

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
            MERGE (g:Group {scope: $scope, identifier: $identifier})
                ON CREATE SET g.created_ts = timestamp()
                ON MATCH SET g.modified_ts = timestamp()
            SET g.display_name = $display_name
            SET g.description = $description
            """
        tx.run(q, scope=group.scope, identifier=group.identifier, display_name=group.display_name,
               description=group.description)

    def _add_or_update_users_and_groups(self, tx: Transaction, group: Group) -> None:
        for user_member in group.user_members:
            self._add_user_to_group(tx, group=group, member=user_member, role=self.Role.MEMBER)
        for group_member in group.group_members:
            self._add_group_to_group(tx, group=group, member=group_member, role=self.Role.MEMBER)
        for user_owner in group.user_owners:
            self._add_user_to_group(tx, group=group, member=user_owner, role=self.Role.OWNER)
        for group_owner in group.group_owners:
            self._add_group_to_group(tx, group=group, member=group_owner, role=self.Role.OWNER)

    def _remove_missing_users_and_groups(self, tx: Transaction, group: Group, role: Role) -> None:
        """ Remove the relationship between group and member if the member no longer is in the groups member list"""

        # Create lists of current members by type
        group_list: List[Group] = []
        user_list: List[User] = []
        if role is self.Role.MEMBER:
            group_list = group.group_members
            user_list = group.user_members
        elif role is self.Role.OWNER:
            group_list = group.group_owners
            user_list = group.user_owners

        # Compare current members with members in the db and remove the excess members
        q = f"""
            MATCH (Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(m)
            RETURN m.scope as scope, m.identifier as identifier, labels(m) as labels
            """
        members_in_db = tx.run(q, scope=group.scope, identifier=group.identifier)
        # NOTICE: tx.sync() will send the transaction up to and including this query so this
        #         should probably be done first or last in the save transaction.
        tx.sync()
        for record in members_in_db:
            if 'Group' in record['labels']:
                member = Group(scope=record['scope'], identifier=record['identifier'])
                if member not in group_list:
                    self._remove_group_from_group(tx, group=group, member=member, role=role)
            elif 'User' in record['labels']:
                member = User(identifier=record['identifier'])
                if member not in user_list:
                    self._remove_user_from_group(tx, group=group, member=member, role=role)

    @staticmethod
    def _remove_group_from_group(tx: Transaction, group: Group, member: Group, role: Role):
        q = f"""
            MATCH (Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(Group
                    {{scope: $member_scope, identifier: $member_identifier}})
            DELETE r
            """
        tx.run(q, scope=group.scope, identifier=group.identifier, member_scope=member.scope,
               member_identifier=member.identifier)

    @staticmethod
    def _remove_user_from_group(tx: Transaction, group: Group, member: User, role: Role):
        q = f"""
            MATCH (Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(User
                    {{identifier: $member_identifier}})
            DELETE r
            """
        tx.run(q, scope=group.scope, identifier=group.identifier, member_identifier=member.identifier)

    @staticmethod
    def _add_group_to_group(tx, group: Group, member: Group, role: Role):
        q = f"""
            MATCH (g:Group {{scope: $group_scope, identifier: $group_identifier}})
            MERGE (m:Group {{scope: $scope, identifier: $identifier}})
                ON CREATE SET
                    m.created_ts = timestamp(),
                    m.display_name = $display_name,
                    m.description = $description
            MERGE (m)-[r:{role.value}]->(g)
                ON CREATE SET r.created_ts = timestamp()
                ON MATCH SET r.modified_ts = timestamp()
            SET r.display_name = $display_name
            """
        tx.run(q, group_scope=group.scope, group_identifier=group.identifier, identifier=member.identifier,
               scope=member.scope, display_name=member.display_name, description=member.description)

    @staticmethod
    def _add_user_to_group(tx, group: Group, member: User, role: Role) -> None:
        q = f"""
            MATCH (g:Group {{scope: $scope, identifier: $group_identifier}})
            MERGE (m:User {{identifier: $identifier}})
            MERGE (m)-[r:{role.value}]->(g)
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

    def remove_group(self, scope: str, identifier: str) -> None:
        q = """
            MATCH (g: Group {scope: $scope, identifier: $identifier})
            DETACH DELETE g
            """
        with self.db.driver.session() as session:
            session.run(q, scope=scope, identifier=identifier)
            session.sync()

    def get_groups_for_user(self, user: User, scope: Optional[str] = None) -> List[Group]:
        res: List[Group] = []
        with_scope = ''

        if scope:
            with_scope = 'WHERE g.scope = $scope'

        q = f"""
            MATCH (User {{identifier: $identifier}})-[IN]->(g: Group)
            {with_scope}
            RETURN g as group
            """

        with self.db.driver.session() as session:
            for record in session.run(q, identifier=user.identifier, scope=scope):
                res.append(Group.from_mapping(record.data()['group']))
        return res

    def save(self, group: Group) -> None:
        with self.db.driver.session() as session:
            try:
                tx = session.begin_transaction()
                self._remove_missing_users_and_groups(tx, group, self.Role.OWNER)
                self._remove_missing_users_and_groups(tx, group, self.Role.MEMBER)
                self._create_or_update_group(tx, group)
                self._add_or_update_users_and_groups(tx, group)
                tx.success = True
            except (ClientError, CypherError) as e:
                logger.error(e)
            finally:
                # If tx.success is not explicitly set to True close will perform a rollback
                tx.close()
