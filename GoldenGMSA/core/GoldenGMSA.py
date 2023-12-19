
from GoldenGMSA.network.LDAP import LDAP
from GoldenGMSA.core.Logger import Logger
from GoldenGMSA.core.gMSAInfo import gMSAInfo
from GoldenGMSA.core.kdsinfo import KDSRootKey

class GoldenGMSA:

    def __init__(self, ldap: LDAP, logger: Logger) -> None:
        self.ldap                   = ldap
        self.logger                 = logger

    def gmsainfo(self, sid: str):
        gMSA = gMSAInfo(self.ldap, self.logger, sid)
        gMSA.run()

    def kdsinfo(self, guid: str):
        kds = KDSRootKey(self.ldap, self.logger, guid)
        kds.run()
