# Solve circular imports of SessionInfo from all over the place by putting it in a 'leaf' file :/
#
from collections.abc import Mapping
from typing import Any, NewType

SessionInfo = NewType("SessionInfo", Mapping[str, Any])
