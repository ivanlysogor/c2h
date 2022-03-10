import abc
from abc import ABC, abstractmethod
from ce import acl

class NetworkDevice(object):

    def __init__(self):
        self.ACLs = []
        self.ObjectGroups = []

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
