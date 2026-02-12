import enum
import logging
from dataclasses import replace
from typing import Any

from bson import ObjectId
from neo4j import READ_ACCESS, WRITE_ACCESS, Record, Transaction
from neo4j.exceptions import ClientError, ConstraintError
from neo4j.graph import Graph, Node

from eduid.graphdb import BaseGraphDB
from eduid.graphdb.exceptions import EduIDGroupDBError, VersionMismatch
from eduid.graphdb.groupdb.group import Group
from eduid.graphdb.groupdb.user import User

__author__ = "lundberg"

logger = logging.getLogger(__name__)


@enum.unique
class Label(enum.Enum):
    # Role to relationship type
    GROUP = "Group"
    USER = "User"


@enum.unique
class Role(enum.Enum):
    # Role to relationship type
    MEMBER = "IN"
    OWNER = "OWNS"


class GroupDB(BaseGraphDB):
    def __init__(self, db_uri: str, scope: str, config: dict[str, Any] | None = None) -> None:
        super().__init__(db_uri=db_uri, config=config)
        self._scope = scope

    def db_setup(self) -> None:
        with self.db.driver.session(default_access_mode=WRITE_ACCESS) as session:
            # new index creation syntax in neo4j >=5.0
            statements = [
                # Constraints for Group nodes
                "CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.scope)",
                "CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.identifier)",
                "CREATE CONSTRAINT ON (n:Group) ASSERT exists(n.version)",
                # Replaced by CREATE CONSTRAINT [name] FOR (node:Label) REQUIRE node.prop IS NOT NULL.
                "CREATE CONSTRAINT ON (n:Group) ASSERT (n.scope, n.identifier) IS NODE KEY",
                # Replaced by CREATE CONSTRAINT [name] FOR (node:Label) REQUIRE (node.prop1,node.prop2) IS NODE KEY.
                # Constraints for User nodes
                "CREATE CONSTRAINT ON (n:User) ASSERT exists(n.identifier)",
                "CREATE CONSTRAINT ON (n:User) ASSERT n.identifier IS UNIQUE",
                # Replaced by CREATE CONSTRAINT [name] FOR (node:Label) REQUIRE node.prop IS UNIQUE
            ]
            for statement in statements:
                try:
                    session.run(statement)
                except ClientError as e:
                    assert e.message is not None  # please mypy
                    acceptable_error_codes = [
                        "Neo.ClientError.Schema.ConstraintAlreadyExists",
                        "Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists",
                    ]
                    # e.message check is neo4j <= 4.1, e.code is neo4j >= 4.4
                    if (
                        "An equivalent constraint already exists" not in e.message
                        and e.code not in acceptable_error_codes
                    ):
                        raise e
                    # Constraints already set up
        logger.info(f"{self} setup done.")

    @property
    def scope(self) -> str:
        return self._scope

    def _create_or_update_group(self, tx: Transaction, group: Group) -> Group:
        q = """
            MERGE (g:Group {scope: $scope, identifier: $identifier, version: $version})
                ON CREATE SET g.created_ts = timestamp()
                ON MATCH SET g.modified_ts = timestamp()
            SET g.display_name = $display_name
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
            new_version=new_version,
        ).single()
        assert res is not None  # please mypy
        return self._load_group(res.data()["group"])

    def _add_or_update_users_and_groups(
        self, tx: Transaction, group: Group
    ) -> tuple[set[User | Group], set[User | Group]]:
        members: set[User | Group] = set()
        owners: set[User | Group] = set()

        for user_member in group.member_users:
            res = self._add_user_to_group(tx, group=group, member=user_member, role=Role.MEMBER)
            if res:
                members.add(User.from_mapping(res.data()))
            else:
                logger.info(f"User {user_member.identifier} not added to group {group.identifier}.")
        for group_member in group.member_groups:
            res = self._add_group_to_group(tx, group=group, member=group_member, role=Role.MEMBER)
            if res:
                members.add(self._load_group(res.data()))
            else:
                logger.info(f"Group {group_member.identifier} not added to group {group.identifier}.")
        for user_owner in group.owner_users:
            res = self._add_user_to_group(tx, group=group, member=user_owner, role=Role.OWNER)
            if res:
                owners.add(User.from_mapping(res.data()))
            else:
                logger.info(f"User {user_owner.identifier} not added to group {group.identifier}.")
        for group_owner in group.owner_groups:
            res = self._add_group_to_group(tx, group=group, member=group_owner, role=Role.OWNER)
            if res:
                owners.add(self._load_group(res.data()))
            else:
                logger.info(f"Group {group_owner.identifier} not added to group {group.identifier}.")
        return members, owners

    def _remove_missing_users_and_groups(self, tx: Transaction, group: Group, role: Role) -> None:
        """Remove the relationship between group and member if the member no longer is in the groups member list"""
        q = f"""
            MATCH (Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(m)
            RETURN m.scope as scope, m.identifier as identifier, labels(m) as labels
            """
        members_in_db = tx.run(q, scope=self.scope, identifier=group.identifier)
        for record in members_in_db:
            if (role is Role.MEMBER and group.has_member(record["identifier"]) is False) or (
                role is Role.OWNER and group.has_owner(record["identifier"]) is False
            ):
                if Label.GROUP.value in record["labels"]:
                    self._remove_group_from_group(tx, group=group, group_identifier=record["identifier"], role=role)
                elif Label.USER.value in record["labels"]:
                    self._remove_user_from_group(tx, group=group, user_identifier=record["identifier"], role=role)

    def _remove_group_from_group(self, tx: Transaction, group: Group, group_identifier: str, role: Role) -> None:
        q = f"""
            MATCH (:Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(:Group
                    {{scope: $scope, identifier: $group_identifier}})
            DELETE r
            """
        tx.run(
            q,
            scope=self.scope,
            identifier=group.identifier,
            group_identifier=group_identifier,
        )

    def _remove_user_from_group(self, tx: Transaction, group: Group, user_identifier: str, role: Role) -> None:
        q = f"""
            MATCH (:Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(:User
                    {{identifier: $user_identifier}})
            DELETE r
            """
        tx.run(q, scope=self.scope, identifier=group.identifier, user_identifier=user_identifier)

    def _add_group_to_group(self, tx: Transaction, group: Group, member: Group, role: Role) -> Record | None:
        q = f"""
            MATCH (g:Group {{scope: $scope, identifier: $group_identifier}})
            MERGE (m:Group {{scope: $scope, identifier: $identifier}})
                ON CREATE SET
                    m.created_ts = timestamp(),
                    m.version = $version,
                    m.display_name = $display_name
            MERGE (m)-[r:{role.value}]->(g)
                ON CREATE SET r.created_ts = timestamp()
                ON MATCH SET r.modified_ts = timestamp()
            SET r.display_name = $display_name
            RETURN r.display_name as display_name, r.created_ts as created_ts, r.modified_ts as modified_ts,
                   m.identifier as identifier, m.scope as scope
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
        ).single()

    def _add_user_to_group(self, tx: Transaction, group: Group, member: User, role: Role) -> Record | None:
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

    def get_users_and_groups_by_role(self, identifier: str, role: Role) -> list[User | Group]:
        res: list[User | Group] = []
        q = f"""
            MATCH (g: Group {{scope: $scope, identifier: $identifier}})<-[r:{role.value}]-(m)
            RETURN r.display_name as display_name, r.created_ts as created_ts, r.modified_ts as modified_ts,
                   m.identifier as identifier, m.scope as scope, m.version as version, labels(m) as labels
            """
        with self.db.driver.session(default_access_mode=READ_ACCESS) as session:
            for record in session.run(q, scope=self.scope, identifier=identifier):
                labels = record.get("labels", [])
                if "User" in labels:
                    res.append(User.from_mapping(record.data()))
                elif "Group" in labels:
                    res.append(self._load_group(record.data()))
        return res

    def get_group(self, identifier: str) -> Group | None:
        q = """
            MATCH (g: Group {scope: $scope, identifier: $identifier})
            OPTIONAL MATCH (g)<-[r]-(m)
            RETURN *
            """
        with self.db.driver.session(default_access_mode=READ_ACCESS) as session:
            group_graph: Graph = session.run(q, scope=self.scope, identifier=identifier).graph()

        if not group_graph.nodes and not group_graph.relationships:
            # group did not exist
            return None

        group_data: Node | None  # please mypy
        if len(group_graph.relationships) == 0:
            # Just a group with no owners or members
            group_data = next(iter(group_graph.nodes))
            assert group_data is not None
            return self._load_group(group_data)
        else:
            # Grab the first relationships end node and create the group from that
            group_data = next(iter(group_graph.relationships)).end_node
            assert group_data is not None
            group = self._load_group(group_data)

            # Iterate over relationships and create owners and members
            for rel in group_graph.relationships:
                assert rel.start_node is not None  # please mypy
                labels = rel.start_node.labels
                # Merge node and relationship data
                data = dict(rel.start_node.items())
                data.update(dict(rel.items()))
                is_owner = rel.type == Role.OWNER.value
                is_member = rel.type == Role.MEMBER.value
                # Instantiate and add owners
                if is_owner and "Group" in labels:
                    group.owners.add(self._load_group(data))
                if is_owner and "User" in labels:
                    group.owners.add(User.from_mapping(data))
                # Instantiate and add members
                if is_member and "Group" in labels:
                    group.members.add(self._load_group(data))
                if is_member and "User" in labels:
                    group.members.add(User.from_mapping(data))
        return group

    def remove_group(self, identifier: str) -> None:
        q = """
            MATCH (g: Group {scope: $scope, identifier: $identifier})
            DETACH DELETE g
            """
        with self.db.driver.session(default_access_mode=WRITE_ACCESS) as session:
            session.run(q, scope=self.scope, identifier=identifier)

    def get_groups_by_property(self, key: str, value: str, skip: int = 0, limit: int = 100) -> list[Group]:
        res: list[Group] = []
        q = f"""
            MATCH (g: Group {{scope: $scope}})
            WHERE g.{key} = $value
            RETURN g as group SKIP $skip LIMIT $limit
            """
        with self.db.driver.session(default_access_mode=READ_ACCESS) as session:
            res = [
                self._load_group(record.data()["group"])
                for record in session.run(q, scope=self.scope, value=value, skip=skip, limit=limit)
            ]
        return res

    def get_groups(self, skip: int = 0, limit: int = 100) -> list[Group]:
        res: list[Group] = []
        q = """
            MATCH (g: Group {scope: $scope})
            RETURN g as group SKIP $skip LIMIT $limit
            """
        with self.db.driver.session(default_access_mode=READ_ACCESS) as session:
            res = [
                self._load_group(record.data()["group"])
                for record in session.run(q, scope=self.scope, skip=skip, limit=limit)
            ]
        return res

    def _get_groups_for_role(self, label: Label, identifier: str, role: Role) -> list[Group]:
        res: list[Group] = []
        if label == Label.GROUP:
            entity_match = "(e:Group {scope: $scope, identifier: $identifier})"
        elif label == Label.USER:
            entity_match = "(e:User {identifier: $identifier})"
        else:
            raise NotImplementedError(f"Label {label.value} not implemented")

        if role is role.OWNER:
            # Return all members only to an owner
            ret_statement = f"""
                            OPTIONAL MATCH (g)<-[r:{Role.MEMBER.value}]-(m)
                            RETURN g as group, owners, collect({{display_name: r.display_name, created_ts: r.created_ts,
                                modified_ts: r.modified_ts, identifier: m.identifier, scope: m.scope}}) as members
                            """
        else:
            # Return only matched entity as member
            ret_statement = f"""
                            OPTIONAL MATCH (g)<-[r:{Role.MEMBER.value}]-(e)
                            RETURN g as group, owners, collect({{display_name: r.display_name, created_ts: r.created_ts,
                                modified_ts: r.modified_ts, identifier: e.identifier, scope: e.scope}}) as members
                            """

        q = f"""
            MATCH {entity_match}-[:{role.value}]->(g: Group {{scope: $scope}})
            WITH e, g
            OPTIONAL MATCH (g)<-[r:{Role.OWNER.value}]-(o)
            WITH e, g, collect({{display_name: r.display_name, created_ts: r.created_ts,
                modified_ts: r.modified_ts, identifier: o.identifier, scope: o.scope}}) as owners
            {ret_statement}
            """
        logger.debug("Crafted _get_groups_for_role query:")
        logger.debug(q)
        with self.db.driver.session(default_access_mode=READ_ACCESS) as session:
            for record in session.run(q, identifier=identifier, scope=self.scope):
                group = self._load_group(record.data()["group"])
                owners = {self._load_node(owner) for owner in record.data()["owners"] if owner.get("identifier")}
                group = replace(group, owners=owners)
                members = {self._load_node(member) for member in record.data()["members"] if member.get("identifier")}
                group = replace(group, members=members)
                res.append(group)
        return res

    def get_groups_for_user_identifer(self, identifier: str) -> list[Group]:
        return self._get_groups_for_role(Label.USER, identifier, role=Role.MEMBER)

    def get_groups_for_group_identifier(self, identifier: str) -> list[Group]:
        return self._get_groups_for_role(Label.GROUP, identifier, role=Role.MEMBER)

    def get_groups_owned_by_user_identifier(self, identifier: str) -> list[Group]:
        return self._get_groups_for_role(Label.USER, identifier, role=Role.OWNER)

    def get_groups_owned_by_group_identifier(self, identifier: str) -> list[Group]:
        return self._get_groups_for_role(Label.GROUP, identifier, role=Role.OWNER)

    def group_exists(self, identifier: str) -> bool:
        q = """
            MATCH (g: Group {scope: $scope, identifier: $identifier})
            RETURN count(*) as exists LIMIT 1
            """
        with self.db.driver.session(default_access_mode=READ_ACCESS) as session:
            single_value = session.run(q, scope=self.scope, identifier=identifier).single()
            assert single_value is not None  # please mypy
            ret = single_value["exists"]
        return bool(ret)

    def save(self, group: Group) -> Group:
        logger.info(f"Saving group with scope {self._scope} and identifier {group.identifier}")
        logger.debug(f"Group: {group}")
        with self.db.driver.session(default_access_mode=WRITE_ACCESS) as session:
            try:
                tx = session.begin_transaction()
            except ClientError as e:
                logger.error(e)
                raise EduIDGroupDBError(e.message) from e
            try:
                self._remove_missing_users_and_groups(tx, group, Role.OWNER)
                self._remove_missing_users_and_groups(tx, group, Role.MEMBER)
                saved_group = self._create_or_update_group(tx, group)
                saved_members, saved_owners = self._add_or_update_users_and_groups(tx, group)
                tx.commit()
            except ConstraintError as e:
                logger.error(e)
                raise VersionMismatch("Tried to save a group with wrong version") from e
            finally:
                if tx.closed():
                    logger.info("Group save successful")
                else:
                    logger.error("Group save error: ROLLING BACK")
                tx.close()
        saved_group = replace(saved_group, members=saved_members, owners=saved_owners)
        return saved_group

    def _load_node(self, data: dict | Node) -> User | Group:
        if data.get("scope"):
            return self._load_group(data=data)
        return self._load_user(data=data)

    @staticmethod
    def _load_group(data: dict | Node) -> Group:
        """Method meant to be overridden by subclasses wanting to annotate the group."""
        return Group.from_mapping(data)

    @staticmethod
    def _load_user(data: dict | Node) -> User:
        """Method meant to be overridden by subclasses wanting to annotate the user."""
        return User.from_mapping(data)
