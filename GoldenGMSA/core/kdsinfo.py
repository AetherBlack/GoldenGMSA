
import base64

from GoldenGMSA.network.LDAP import LDAP
from GoldenGMSA.core.Logger import Logger

class KDSRootKey:

    def __init__(self, ldap: LDAP, logger: Logger, guid: str) -> None:
        self.ldap = ldap
        self.logger = logger

        self.kdsRootKeys = self.ldap.getAllKDSKey(guid)

    def run(self) -> None:
        if not len(self.kdsRootKeys):
            self.logger.error("No entries found!")
            return

        for kdsRootKey in self.kdsRootKeys:

            rootKey = base64.b64encode(kdsRootKey.msKdsRootKeyData).decode()
            
            self.logger.information(f"GUID: {kdsRootKey.cn}")
            self.logger.information(f"blob: {rootKey}")
