
from ldap3.protocol.formatters.formatters import format_sid

class ADObject:

    def __init__(self) -> None:
        pass

    def convertSid(self, objectSid: bytes) -> str:
        return format_sid(objectSid)

    def __str__(self) -> str:
        return "{0: <30} {1}".format(self.sAMAccountName, self.objectSid)
