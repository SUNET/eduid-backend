from typing import Annotated, Any

from bson import ObjectId
from jwcrypto.common import JWException
from jwcrypto.jwk import JWK
from pydantic import AnyUrl, GetCoreSchemaHandler, GetJsonSchemaHandler, HttpUrl
from pydantic.json_schema import JsonSchemaValue
from pydantic_core import core_schema

__author__ = "lundberg"

AnyUrlStr = Annotated[str, AnyUrl]
HttpUrlStr = Annotated[str, HttpUrl]


# https://docs.pydantic.dev/2.6/concepts/types/#handling-third-party-types
class ObjectIdPydanticAnnotation:
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Any, _handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        """
        We return a pydantic_core.CoreSchema that behaves in the following ways:

        * strs will be parsed as `ObjectId` instances
        * `ObjectId` instances will be parsed as `ObjectId` instances without any changes
        * Nothing else will pass validation
        * Serialization will always return just a str
        """

        def validate_from_str(value: str) -> ObjectId:
            return ObjectId(value)

        from_str_schema = core_schema.chain_schema(
            [
                core_schema.str_schema(),
                core_schema.no_info_plain_validator_function(validate_from_str),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_str_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(ObjectId),
                    from_str_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda instance: str(instance)),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, _core_schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        # Use the same schema that would be used for `str`
        return handler(core_schema.str_schema())


class JWKPydanticAnnotation:
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type: Any, _handler: GetCoreSchemaHandler) -> core_schema.CoreSchema:
        """
        We return a pydantic_core.CoreSchema that behaves in the following ways:

        * json will be parsed as `JWK` instances
        * `JWK` instances will be parsed as `JWK` instances without any changes
        * Nothing else will pass validation
        * Serialization will always return just a dict
        """

        def validate_from_dict(value: dict[str, str]) -> JWK:
            try:
                return JWK(**value)
            except (KeyError, JWException) as e:
                raise ValueError(str(e))

        def serialize_to_dict(instance: JWK) -> dict[str, str]:
            # JWK inherits from dict, so we can just return it
            return instance

        from_dict_schema = core_schema.chain_schema(
            [
                core_schema.dict_schema(),
                core_schema.no_info_plain_validator_function(validate_from_dict),
            ]
        )

        return core_schema.json_or_python_schema(
            json_schema=from_dict_schema,
            python_schema=core_schema.union_schema(
                [
                    # check if it's an instance first before doing any further work
                    core_schema.is_instance_schema(JWK),
                    from_dict_schema,
                ]
            ),
            serialization=core_schema.plain_serializer_function_ser_schema(serialize_to_dict),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, _core_schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> JsonSchemaValue:
        # Use the same schema that would be used for `dict[str, str]`
        return handler(
            core_schema.dict_schema(keys_schema=core_schema.str_schema(), values_schema=core_schema.str_schema())
        )
