import logging
from collections.abc import Mapping
from typing import Any

import satosa.context
import satosa.internal
from satosa.micro_services.base import ResponseMicroService
from satosa.routing import STATE_KEY as ROUTER_STATE_KEY
from satosa.util import get_dict_defaults

logger = logging.getLogger(__name__)

# Type describing this microservice's configuration data
StaticAttributesConfig = dict[str, list[dict[str, str]]]
StaticAppendedAttributesConfig = dict[str, list[dict[str, str]]]


class AddStaticAttributesForVirtualIdp(ResponseMicroService):
    """
    A class that add static attributes to a response set.
    The following example configuration illustrates most common features:
    ```yaml
    module: eduid.satosa.scimapi.static_attributes.AddStaticAttributesForVirtualIdp
    name: AddStaticAttributesForVirtualIdp
    config:
        static_attributes_for_virtual_idp:
            requester1:
                virtual_idp_1:
                    schachomeorganization:
                      - foo
            default:
                virtual_idp_1:
                    schachomeorganization:
                      - bar
                virtual_idp_2:
                    schachomeorganization:
                      - fax
        static_appended_attributes_for_virtual_idp:
            default:
                virtual_idp_1:
                    edupersonassurance:
                        - https://refeds.org/assurance/ATP/ePA-1m
                        - https://refeds.org/assurance/IAP/local-enterprise
    ```
    The use of "" and 'default' is synonymous. Attribute rules are not overloaded
    or inherited. For instance a response for "requester1" from virtual_idp_1 in
    the above config will generate a static attribute with value 'foo'
    schachomeorganization attribute and nothing else. Note that static attributes
    override existing attributes if present.
    """

    def __init__(self, config: Mapping[str, Any], *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.static_attributes: StaticAttributesConfig | None = config.get("static_attributes_for_virtual_idp")
        self.static_appended_attributes: StaticAppendedAttributesConfig | None = config.get(
            "static_appended_attributes_for_virtual_idp"
        )

    def _build_static(self, requester: str, vidp: str, existing_attributes: dict) -> dict[str, list[str]]:
        static_attributes: dict[str, list[str]] = dict()

        if self.static_attributes:
            recipes: Mapping[str, list] = get_dict_defaults(self.static_attributes, requester, vidp)
            for attr_name, fmt in recipes.items():
                logger.debug(f"Adding static attribute {attr_name}: {fmt} for requester {requester} or {vidp}")

                static_attributes[attr_name] = fmt

        if self.static_appended_attributes:
            recipes = get_dict_defaults(self.static_appended_attributes, requester, vidp)
            for attr_name, fmt in recipes.items():
                static_attributes[attr_name] = fmt
                if attr_name in existing_attributes:
                    for value in existing_attributes[attr_name]:
                        if value not in fmt:
                            static_attributes[attr_name].append(value)
                    static_attributes[attr_name].sort()
                else:
                    static_attributes[attr_name] = fmt


                logger.debug(f"Appending static attribute {attr_name}: {fmt} for requester {requester} or {vidp}")

        return static_attributes

    def process(
        self, context: satosa.context.Context, data: satosa.internal.InternalData
    ) -> satosa.internal.InternalData:
        if context.state is not None and isinstance(data.requester, str) and data.attributes is not None:
            virtual_idp: str = context.state.get(ROUTER_STATE_KEY)
            data.attributes.update(self._build_static(data.requester, virtual_idp, data.attributes))
        return super().process(context, data)
