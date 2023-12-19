
from typing import List

from GoldenGMSA.structures.ADObject import ADObject

class ADGMSA(ADObject):

    def __init__(self, **kwargs: dict) -> None:
        self.distinguishedName: str             = kwargs["distinguishedName"][0].decode()
        self.objectSid: str                     = self.convertSid(kwargs["objectSid"][0])
        self.sAMAccountName: str                = kwargs["sAMAccountName"][0].decode().lower()
        self.msDSManagedPasswordId: bytes       = kwargs["msDS-ManagedPasswordId"][0]
        self.msDSGroupMSAMembership: bytes      = kwargs["msDS-GroupMSAMembership"][0]
        # It's possible that this value will be empty
        self.msDSManagedPassword: List[bytes]   = kwargs.get("msDS-ManagedPassword", [])
