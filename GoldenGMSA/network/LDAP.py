
from typing import List

import ssl as tls
import ldap3
import ldap3.core.exceptions as ldap3_exceptions

from GoldenGMSA.structures.Credentials import Credentials
from GoldenGMSA.structures.Target import Target
from GoldenGMSA.network.Kerberos import Kerberos
from GoldenGMSA.core.Logger import Logger
from GoldenGMSA.structures.ADObject.ADGMSA import ADGMSA
from GoldenGMSA.structures.ADObject.ADKDSKey import ADKDSKey

class LDAP:

    gMSAAccount = list()
    kdsKey = list()

    def __init__(self, target: Target, credentials: Credentials, logger: Logger) -> None:
        self.target         = target
        self.credentials    = credentials
        self.logger         = logger

        self.__getPort()
        self.__checkAuthentication()

    def __getPort(self) -> None:
        if self.target.port:
            return

        self.target.port, self.target.tlsv1_2 = self.__tryLDAPS(tls.PROTOCOL_TLSv1_2, self.target.port)

        if self.target.tlsv1_2 is None:
            self.target.port, self.target.tlsv1 = self.__tryLDAPS(tls.PROTOCOL_TLSv1, self.target.port)

            if self.target.tlsv1 is None:
                self.target.port = self.__tryLDAP(self.target.port)

        if self.target.port is None:
            self.logger.error(f"Impossible to communicate with the target {self.target.remote} !")
            exit(1)

    def __checkAuthentication(self) -> None:
        self.logger.debug("Trying to connect to %s:%d" % (self.target.remote, self.target.port))
        self.__Authentication()

        try:
            self.getNamingContexts()
        except IndexError:
            self.logger.error("Invalid credentials !")
            exit(1)

        self.logger.debug("Authentication success !")

    def __Authentication(self) -> ldap3.Connection:
        user = "%s\\%s" % (self.credentials.domain, self.credentials.username)

        ldapTls = None

        if self.target.tlsv1_2:
            ldapTls = ldap3.Tls(validate=tls.CERT_NONE, version=tls.PROTOCOL_TLSv1_2, ciphers='ALL:@SECLEVEL=0')
        elif self.target.tlsv1:
            ldapTls = ldap3.Tls(validate=tls.CERT_NONE, version=tls.PROTOCOL_TLSv1, ciphers='ALL:@SECLEVEL=0')

        ldapServer = ldap3.Server(self.target.remote, use_ssl=self.target.use_tls(), port=self.target.port, get_info=ldap3.ALL, tls=ldapTls)

        if self.credentials.doKerberos:
            ldapConn = ldap3.Connection(ldapServer)
            ldapConn = self.kerberosAuthentication(ldapConn)
        else:
            ldapConn = ldap3.Connection(ldapServer, user=user, password=self.credentials.getAuthenticationSecret(), authentication=ldap3.NTLM)
            try:
                ldapConn.bind()
            except ldap3_exceptions.LDAPSocketReceiveError:
                self.logger.error("Error connecting! Try using -use-ldaps")
                exit(1)
            except ldap3_exceptions.LDAPSocketOpenError:
                self.logger.error("Error connecting! Try using without -use-ldaps")
                exit(1)

        if ldapConn.result["description"] == "invalidCredentials":
            self.logger.error("Invalid credentials !")
            exit(1)

        return ldapConn

    def __tryLDAPS(self, proto: tls._SSLMethod, port: int) -> int:
        port = port or 636

        ldapTls = ldap3.Tls(validate=tls.CERT_NONE, version=proto, ciphers="ALL:@SECLEVEL=0")
        ldapServer = ldap3.Server(self.target.remote, use_ssl=True, port=port, get_info=ldap3.ALL, tls=ldapTls)
        ldapConn = ldap3.Connection(ldapServer)

        try:
            ldapConn.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return None, None
        except ldap3.core.exceptions.LDAPSocketReceiveError:
            pass

        return port, True

    def __tryLDAP(self, port: int) -> int:
        self.logger.debug("LDAPS failed, trying with LDAP.")
        port = port or 389

        ldapServer = ldap3.Server(self.target.remote, use_ssl=False, port=port, get_info=ldap3.ALL)
        ldapConn = ldap3.Connection(ldapServer)

        try:
            ldapConn.bind()
        except ldap3.core.exceptions.LDAPSocketOpenError:
            return None
        except ldap3.core.exceptions.LDAPSocketReceiveError:
            return port

        return port

    def kerberosAuthentication(self, ldapConn: ldap3.Connection) -> None:
        blob = Kerberos.kerberosLogin(self.target.remote, self.credentials.username, self.credentials.password,
                                    self.credentials.domain, self.credentials.ntlmhash, self.credentials.aesKey,
                                    kdcHost=self.target.remote)

        request = ldap3.operation.bind.bind_operation(ldapConn.version, ldap3.SASL, self.credentials.username, None, "GSS-SPNEGO", blob.getData())

        # Done with the Kerberos saga, now let's get into LDAP
        # try to open connection if closed
        if ldapConn.closed:
            ldapConn.open(read_server_info=False)

        ldapConn.sasl_in_progress = True
        response = ldapConn.post_send_single_response(ldapConn.send('bindRequest', request, None))

        ldapConn.sasl_in_progress = False

        if response[0]['result'] != 0:
            raise Exception(response)

        ldapConn.bound = True

        return ldapConn
    
    def search(self, dn: str, filter: str, scope: str, attributes: list = ["*"]) -> list:
        ldapConn = self.__Authentication()
        ldapConn.search(
            search_base=dn,
            search_filter=filter,
            search_scope=scope,
            attributes=attributes,
            # Controls to get nTSecurityDescriptor from standard user
            # OWNER_SECURITY_INFORMATION + GROUP_SECURITY_INFORMATION + DACL_SECURITY_INFORMATION
            controls=[("1.2.840.113556.1.4.801", True, "%c%c%c%c%c" % (48, 3, 2, 1, 7), )]
        )
        return ldapConn.response

    def __createArrayOfObject(self, response: list, obj: object) -> list:

        array = list()

        for entry in response:
            # Not a response object
            if entry["type"] != "searchResEntry":
                continue

            array.append(
                obj(**entry["raw_attributes"])
            )

        return array

    def getNamingContexts(self) -> list:
        response = self.search(
            "",
            "(objectClass=*)",
            ldap3.BASE,
            ["namingContexts"]
        )

        self.namingContexts = response[0]["attributes"]["namingContexts"]
        self.defaultNamingContext = self.namingContexts[0]
        self.configurationNamingContext = self.namingContexts[1]
        self.schemaNamingContext = self.namingContexts[2]
        self.domainDnsZonesNamingContext = self.namingContexts[3]
        self.forestDnsZonesNamingContext = self.namingContexts[4]

    def getAllGMSAAccount(self, sid: str) -> List[ADGMSA]:
        if len(self.gMSAAccount):
            return self.gMSAAccount
        
        filter = "(objectClass=msDS-GroupManagedServiceAccount)"
        attributes = [
            "distinguishedName",
            "objectSid",
            "sAMAccountName",
            "msDS-ManagedPasswordID",
            "msDS-GroupMSAMembership"
        ]

        if isinstance(sid, str):
            filter = f"(&(objectClass=msDS-GroupManagedServiceAccount)(objectSid={sid}))"

        if self.target.use_tls():
            attributes.append("msDS-ManagedPassword")
        
        response = self.search(
            self.defaultNamingContext,
            filter,
            ldap3.SUBTREE,
            attributes
        )

        self.gMSAAccount = self.__createArrayOfObject(response, ADGMSA)

        return self.gMSAAccount

    def getAllKDSKey(self, guid: str) -> List[ADKDSKey]:
        if len(self.kdsKey):
            return self.kdsKey
        
        filter = "(objectClass=msKds-ProvRootKey)"
        attributes = [
            "msKds-SecretAgreementParam",
            "msKds-RootKeyData",
            "msKds-KDFParam",
            "msKds-KDFAlgorithmID",
            "msKds-CreateTime",
            "msKds-UseStartTime",
            "msKds-Version",
            "msKds-DomainID",
            "cn",
            "msKds-PrivateKeyLength",
            "msKds-PublicKeyLength",
            "msKds-SecretAgreementAlgorithmID"
        ]

        if isinstance(guid, str):
            filter = f"(&(objectClass=msKds-ProvRootKey)(cn={guid}))"
        
        response = self.search(
            self.configurationNamingContext,
            filter,
            ldap3.SUBTREE,
            attributes
        )

        self.kdsKey = self.__createArrayOfObject(response, ADKDSKey)

        return self.kdsKey
