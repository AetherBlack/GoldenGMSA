
from GoldenGMSA.structures.ADObject import ADObject

class ADKDSKey(ADObject):

    def __init__(self, **kwargs) -> None:
        self.cn = kwargs["cn"][0].decode()
        self.msKdsRootKeyData   = kwargs["msKds-RootKeyData"][0]

        self.sAMAccountName = self.cn
        self.objectSid = str()
