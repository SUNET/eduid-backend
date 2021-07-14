from enum import Enum, unique


@unique
class IdPAction(str, Enum):
    PWAUTH = 'USERNAMEPASSWORD'
    MFA = 'MFA'
    TOU = 'TOU'
    FINISHED = 'FINISHED'
