# GoldenGMSA.

from impacket.structure import Structure
from impacket.uuid import bin_to_string

import struct


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        ('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self, data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]

class MSDS_MANAGEDPASSWORDID_BLOB(Structure):

    structure = (
        ('Version','<L'),
        ('Reserved','<L'),
        ('isPublicKey','<L'),
        ('L0Index','<L'),
        ('L1Index','<L'),
        ('L2Index','<L'),
        ('RootKeyIdentifier',':'),
        ('cbUnknown',':'),
        ('cbDomainName',':'),
        ('cbForestName',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self, data)

        self["RootKeyIdentifier"] = bin_to_string(self.rawData[24 : 24 + 16]).lower()
        self["cbUnknown"] = struct.unpack("<L", self.rawData[40:44])[0]
        self["cbDomainName"] = struct.unpack("<L", self.rawData[44:48])[0]
        self["cbForestName"] = struct.unpack("<L", self.rawData[48:52])[0]

        if self["cbUnknown"] > 0:
            self["Unknown"] = self.rawData[52 : 52 + self["cbUnknown"]]
        else:
            self["Unknown"] = None
        
        self["DomainName"] = self.rawData[52 + self["cbUnknown"] : self["cbDomainName"]]
        self["ForestName"] = self.rawData[52 + self["cbUnknown"] + self["cbDomainName"] : self["cbForestName"]]
