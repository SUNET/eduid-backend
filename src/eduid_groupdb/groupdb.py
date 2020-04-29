# -*- coding: utf-8 -*-
import enum
import logging
from typing import Dict, List, Optional, Tuple, Union

from bson import ObjectId
from neo4j import Record, Transaction
from neo4j.exceptions import ClientError, ConstraintError, CypherError
from neo4j.types.graph import Graph
from neobolt.routing import READ_ACCESS, WRITE_ACCESS

from eduid_groupdb import BaseGraphDB, Group, User
from eduid_groupdb.exceptions import EduIDGroupDBError, VersionMismatch

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class GroupDB(BaseGraphDB):
    @enum.unique
    class Role(enum.Enum):
        # Role to relationship type
        MEMBER = 'IN'
        OWNER = 'OWNS'

    def db_setup(self):
        with self.db.driver.session(access_mode=WRITE_ACCESS) as session:
            statements = [
                # Constraints for Group nodes
                'CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.scope)',
                'CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.identifier)',
                'CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.version)',
                'CREATE CONSTRAINT ON (n:Group) ASSERT (n.scope, n.identifier) IS NODE KEY',
                # Constraints for User nodes
                'CREATE CONSTRAINT ON (n:User) ASSERT exists(n.identifier)',
                'CREATE CONSTRAINT ON (n:User) ASSERT n.identifier IS UNIQUE',
            ]
            for statment in statements:
                try:
                    session.run(statment)
                except ClientError as e:
                    if 'An equivalent constraint already exists' not in e.message:
                        raise e
                    # Constraints already set up
                    pass
        logger.info(f'{self} setup done.')

    def _create_or_update_group(self, tx: Transaction, group: Group) -> Group:
        q = """
            MERGE (g:Group {scope: $scope, identifier: $identifier, version: $version})
                ON CREATE SET g.created_ts = timestamp()
                ON MATCH SET g.modified_ts = timestamp()
            SET g.display_name = $display_name
            SET g.description = $description
            SET g.version = $new_version
            RETURN g as group
            """
        if group.version is None:
            version = str(ObjectId())
        else:
            version = str(group.version)
        new_version = str(ObjectId())
        res = tx.run(
            q,
            scope=self.scope,
            identifier=group.identifier,
            version=version,
            display_name=group.display_name,
            description=group.description,
            new_version=new_version,
        ).single()
        return self._load_group(res.data()['group'])

    def _add_or_update_users_and_groups(
        self, tx: Transaction, group: Group
    ) -> Tuple[List[Union[User, Group]], List[Union[User, Group]]]:
        members: List[Union[User, Group]] = []
        owners: List[Union[User, Group]] = []

        for user_member in group.member_users:
            res = self._add_user_to_group(tx, group=group, member=user_member, role=self.Role.MEMBER)
            members.append(User.from_mapping(res.data()))
        for group_member in group.member_groups:
            res = self._add_group_to_group(tx, group=group, member=group_member, role=self.Role.MEMBER)
            members.append(self._load_group(res.data()))
        for user_owner in group.owner_users:
            res = self._add_user_to_group(tx, group=group, member=user_owner, role=self.Role.OWNER)
            owners.append(User.from_mapping(res.data()))
        for group_owner in group.owner_groups:
            res = self._add_group_to_group(tx, group=group, member=group_owner, role=self.Role.OWNER)
            owners.append(self._load_group(res.data()))
        return members, owners

    def _remove_missing_users_and_groups(self, tx: Transaction, group: Group, role: Role) -> None:
        """ Remove the relationship between group and member if the member no longer is in the groups member list"""

        # Create lists of current members by type
        group_list: List[Group] = []
        user_list: List[User] = []
        if role is self.Role.MEMBER:
            group_list = group.member_groups
            user_list = group.member_users
        elif role is self.Role.OWNER:
            group_list = group.owner_groups
            user_list = group.owner_users

        # Compare current members with members in the db and remove the excess members
        q = f"""
            MATCH (Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(m)
            RETURN m.scope as scope, m.identifier as identifier, labels(m) as labels
            """
        members_in_db = tx.run(q, scope=self.scope, identifier=group.identifier)
        # NOTICE: tx.sync() will send the transaction up to and including this query so this
        #         should probably be done first or last in the save transaction.
        tx.sync()
        for record in members_in_db:
            if 'Group' in record['labels']:
                group_member = Group(identifier=record['identifier'])
                if group_member not in group_list:
                    self._remove_group_from_group(tx, group=group, member=group_member, role=role)
            elif 'User' in record['labels']:
                user_member = User(identifier=record['identifier'])
                if user_member not in user_list:
                    self._remove_user_from_group(tx, group=group, member=user_member, role=role)

    def _remove_group_from_group(self, tx: Transaction, group: Group, member: Group, role: Role):
        q = f"""
            MATCH (Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(Group
                    {{scope: $scope, identifier: $member_identifier}})
            DELETE r
            """
        tx.run(
            q, scope=self.scope, identifier=group.identifier, member_identifier=member.identifier,
        )

    def _remove_user_from_group(self, tx: Transaction, group: Group, member: User, role: Role):
        q = f"""
            MATCH (Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(User
                    {{identifier: $member_identifier}})
            DELETE r
            """
        tx.run(q, scope=self.scope, identifier=group.identifier, member_identifier=member.identifier)

    def _add_group_to_group(self, tx, group: Group, member: Group, role: Role) -> Record:
        q = f"""
            MATCH (g:Group {{scope: $scope, identifier: $group_identifier}})
            MERGE (m:Group {{scope: $scope, identifier: $identifier}})
                ON CREATE SET
                    m.created_ts = timestamp(),
                    m.version = $version,
                    m.display_name = $display_name,
                    m.description = $description
            MERGE (m)-[r:{role.value}]->(g)
                ON CREATE SET r.created_ts = timestamp()
                ON MATCH SET r.modified_ts = timestamp()
            SET r.display_name = $display_name
            RETURN r.display_name as display_name, r.created_ts as created_ts, r.modified_ts as modified_ts,
                   m.identifier as identifier, m.scope as scope, m.description as description
            """
        # Need a version if the group is created
        version = str(ObjectId())
        return tx.run(
            q,
            scope=self.scope,
            group_identifier=group.identifier,
            identifier=member.identifier,
            version=version,
            display_name=member.display_name,
            description=member.description,
        ).single()

    def _add_user_to_group(self, tx, group: Group, member: User, role: Role) -> Record:
        q = f"""
            MATCH (g:Group {{scope: $scope, identifier: $group_identifier}})
            MERGE (m:User {{identifier: $identifier}})
            MERGE (m)-[r:{role.value}]->(g)
                ON CREATE SET r.created_ts = timestamp()
                ON MATCH SET r.modified_ts = timestamp()
            SET r.display_name = $display_name
            RETURN r.display_name as display_name, r.created_ts as created_ts, r.modified_ts as modified_ts,
                   m.identifier as identifier
            """
        return tx.run(
            q,
            scope=self.scope,
            group_identifier=group.identifier,
            identifier=member.identifier,
            display_name=member.display_name,
        ).single()

    def _get_users_and_groups_by_role(self, identifier: str, role: Role) -> List[Union[User, Group]]:
        res: List[Union[User, Group]] = []
        q = f"""
            MATCH (g: Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(m)
            RETURN r.display_name as display_name, r.created_ts as created_ts, r.modified_ts as modified_ts,
                   m.identifier as identifier, m.scope as scope, m.version as version, m.description as description,
                   labels(m) as labels
            """
        with self.db.driver.session(access_mode=READ_ACCESS) as session:
            for record in session.run(q, scope=self.scope, identifier=identifier):
                labels = record.get('labels', [])
                if 'User' in labels:
                    res.append(User.from_mapping(record.data()))
                elif 'Group' in labels:
                    res.append(self._load_group(record.data()))
        return res

    def get_group(self, identifier: str) -> Optional[Group]:
        q = """
            MATCH (g: Group {scope: $scope, identifier: $identifier})
            OPTIONAL MATCH (g)<-[r]-(m)
            RETURN *
            """
        with self.db.driver.session(access_mode=READ_ACCESS) as session:
            group_graph: Graph = session.run(q, scope=self.scope, identifier=identifier).graph()

        if not group_graph.nodes and not group_graph.relationships:
            # group did not exist
            return None

        if len(group_graph.relationships) == 0:
            # Just a group with no owners or members
            group_data = [node_data for node_data in group_graph.nodes][0]
            return self._load_group(group_data)
        else:
            # Grab the first relationships end node and create the group from that
            group_data = [node_data.end_node for node_data in group_graph.relationships][0]
            group = self._load_group(group_data)

            # Iterate over relationships and create owners and members
            for rel in group_graph.relationships:
                labels = rel.start_node.labels
                # Merge node and relationship data
                data = dict(rel.start_node.items())
                data.update(dict(rel.items()))
                is_owner = rel.type == self.Role.OWNER.value
                is_member = rel.type == self.Role.MEMBER.value
                # Instantiate and add owners
                if is_owner and 'Group' in labels:
                    group.owners.append(self._load_group(data))
                if is_owner and 'User' in labels:
                    group.owners.append(User.from_mapping(data))
                # Instantiate and add members
                if is_member and 'Group' in labels:
                    group.members.append(self._load_group(data))
                if is_member and 'User' in labels:
                    group.members.append(User.from_mapping(data))
        return group

    def remove_group(self, identifier: str) -> None:
        q = """
            MATCH (g: Group {scope: $scope, identifier: $identifier})
            DETACH DELETE g
            """
        with self.db.driver.session(access_mode=WRITE_ACCESS) as session:
            session.run(q, scope=self.scope, identifier=identifier)

    def get_groups_by_property(self, key: str, value: str, skip=0, limit=100):
        res: List[Group] = []
        q = f"""
            MATCH (g: Group {{scope: $scope}})
            WHERE g.{key} = $value
            RETURN g as group SKIP $skip LIMIT $limit
            """
        with self.db.driver.session(access_mode=READ_ACCESS) as session:
            for record in session.run(q, scope=self.scope, value=value, skip=skip, limit=limit):
                res.append(self._load_group(record.data()['group']))
        return res

    def get_groups(self):
        res: List[Group] = []
        q = """
            MATCH (g: Group {scope: $scope})
            RETURN g as group
            """
        with self.db.driver.session(access_mode=READ_ACCESS) as session:
            for record in session.run(q, scope=self.scope):
                res.append(self._load_group(record.data()['group']))
        return res

    def get_groups_for_user(self, user: User) -> List[Group]:
        res: List[Group] = []
        with_scope = ''

        # TODO: this seems to be the only place where scope is Optional?
        if self.scope:
            with_scope = 'WHERE g.scope = $scope'

        q = f"""
            MATCH (User {{identifier: $identifier}})-[IN]->(g: Group)
            {with_scope}
            RETURN g as group
            """

        with self.db.driver.session(access_mode=READ_ACCESS) as session:
            for record in session.run(q, identifier=user.identifier, scope=self.scope):
                res.append(self._load_group(record.data()['group']))
        return res

    def group_exists(self, identifier: str) -> bool:
        q = """
            MATCH (g: Group {scope: $scope, identifier: $identifier})             
            RETURN count(*) as exists LIMIT 1
            """
        with self.db.driver.session(access_mode=READ_ACCESS) as session:
            ret = session.run(q, scope=self.scope, identifier=identifier).single()['exists']
        return bool(ret)

    def save(self, group: Group) -> Group:
        with self.db.driver.session(access_mode=WRITE_ACCESS) as session:
            try:
                tx = session.begin_transaction()
                self._remove_missing_users_and_groups(tx, group, self.Role.OWNER)
                self._remove_missing_users_and_groups(tx, group, self.Role.MEMBER)
                saved_group = self._create_or_update_group(tx, group)
                saved_members, saved_owners = self._add_or_update_users_and_groups(tx, group)
                tx.success = True
            except ConstraintError as e:
                logger.error(e)
                raise VersionMismatch('Tried to save a group with wrong version')
            except (ClientError, CypherError) as e:
                logger.error(e)
                raise EduIDGroupDBError(e.message)
            finally:
                # If tx.success is not explicitly set to True close will perform a rollback
                tx.close()
        saved_group.members = saved_members
        saved_group.owners = saved_owners
        return saved_group

    def _load_group(self, data: Dict) -> Group:
        """ Method meant to be overridden by subclasses wanting to annotate the groups. """
        return Group.from_mapping(data)
