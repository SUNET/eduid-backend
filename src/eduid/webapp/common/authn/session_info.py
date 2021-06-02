# Solve circular imports of SessionInfo from all over the place by putting it in a 'leaf' file :/
#
from typing import Any, Mapping, NewType

SessionInfo = NewType('SessionInfo', Mapping[str, Any])
