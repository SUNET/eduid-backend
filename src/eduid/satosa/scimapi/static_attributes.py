import logging
from typing import Any, Mapping

import satosa.context
import satosa.internal
from satosa.micro_services.base import ResponseMicroService
from satosa.routing import STATE_KEY as ROUTER_STATE_KEY
from satosa.util import get_dict_defaults

logger = logging.getLogger(__name__)

# Type describing this microservice's configuration data
StaticAttributesConfig = dict[str, list[dict[str, str]]]

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
                    schachomeorganization: foo
            default:
                virtual_idp_1:
                    schachomeorganization: bar
                virtual_idp_2:
                    schachomehrganization: fax
    ```
    The use of "" and 'default' is synonymous. Attribute rules are not overloaded
    or inherited. For instance a response for "requester1" from virtual_idp_1 in
    the above config will generate a static attribute with value 'foo'
    schachomeorganization attribute and nothing else. Note that static attributes
    override existing attributes if present.
    """

    def __init__(self, config: Mapping[str, Any], *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.static_attributes: StaticAttributesConfig = config["static_attributes_for_virtual_idp"]

    def _build_static(self, requester: str, vidp: str):
        static_attributes: dict[str, list] = dict()

        recipes: Mapping[str, list] = get_dict_defaults(self.static_attributes, requester, vidp)
        for attr_name, fmt in recipes.items():
            logger.debug(f"Adding static attribut {attr_name}: {fmt} for {vidp}")

            static_attributes[attr_name] = fmt

        return static_attributes

    def process(self, context: satosa.context.Context, data: satosa.internal.InternalData):
        virtual_idp: str = context.state.get(ROUTER_STATE_KEY)
        data.attributes.update(self._build_static(data.requester, virtual_idp))
        return super().process(context, data)
