import abc
from abc import ABC, abstractmethod
from ce import acl

class NetworkDevice(object):

    def __init__(self):
        self.ACLs = []
        self.ObjectGroups = []

    def MaskToWildcard(self, mask):
        Octets = mask.split(".")
        for i in range(len(Octets)):
            Octets[i] = str(255-int(Octets[i]))
        return f"{Octets[0]}.{Octets[1]}.{Octets[2]}.{Octets[3]}"

    def GetObjectGroup(self, Name):
        for obj in self.ObjectGroups:
            if obj.Name == Name:
                return obj
        return None

    @abstractmethod
    def GenerateAcl(self):
        pass

    @abstractmethod
    def ParseConfigFromFile(self, file_name):
        pass
