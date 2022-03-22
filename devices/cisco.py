from ce import Acl, AclL3Entry, ACL_BASIC, ACL_EXTENDED, \
    ObjectGroup, ObjectGroupServiceEntry, ObjectGroupHostEntry, OBJ_SERVICE, OBJ_NETWORK, \
    L3_PROTO, L4_PROTO
from .device import NetworkDevice
from helpers import logger
from ciscoconfparse import CiscoConfParse
import re


class CiscoNetworkDevice(NetworkDevice):

    def ParseObjectGroupsFromFile(self, file_name):
        conf = CiscoConfParse(file_name)
        objs = conf.find_objects("^object-group")
        logger.debug('Parsing ObjectGroups')
        for obj in objs:
            logger.debug(f"Parsing object-group {obj.text}")
            obj_attributes = re.search("^object-group (\S+) (\S+)", obj.text)
            obj_type = obj_attributes[1]
            obj_name = obj_attributes[2]
            if obj_type == "network":
                obj_type_id = OBJ_NETWORK
            elif obj_type == "service":
                obj_type_id = OBJ_SERVICE
            else:
                logger.info(f"Unknown object-group type")
                continue
            new_obj = ObjectGroup(Type=obj_type_id, Name=obj_name)
            for entry in obj.all_children:
                logger.debug(f"Parsing object-group entry {entry.text}")
                entry_attributes = re.search("^ description (.*)", entry.text)
                # Description
                if entry_attributes:
                    logger.debug(f"Description {entry_attributes[1]}")
                    new_obj.Description = entry_attributes[1]
                    continue
                if obj_type_id == OBJ_NETWORK:
                    #  host 195.19.222.171
                    #  172.24.4.0 255.255.255.192
                    entry_attributes = re.search("(\S+) (\S+)", entry.text)
                    if entry_attributes:
                        if entry_attributes[1] == "host":
                            new_entry = ObjectGroupHostEntry(Host=entry_attributes[2])
                        else:
                            new_entry = ObjectGroupHostEntry(IPAddress=entry_attributes[1], \
                                                             Mask=self.MaskToWildcard(entry_attributes[2]))
                        new_obj.Entries.append(new_entry)
                    else:
                        logger.info(f"Unable to parse entry")
                if obj_type_id == OBJ_SERVICE:
                    #  tcp range 49152 65535
                    #  tcp eq 445
                    #  tcp-udp eq 3389
                    #  tcp source eq 22
                    #  tcp source eq 445
                    #  tcp-udp source eq 3389
                    entry_attributes = re.split(r'\s{1,}', entry.text[1:])
                    if entry_attributes:
                        logger.debug(f"Parsing object-group entry {entry_attributes}")
                        attr_id = 0
                        new_entry = ObjectGroupServiceEntry(Proto=entry_attributes[attr_id])
                        attr_id += 1
                        if attr_id < len(entry_attributes[attr_id]) and \
                                re.match("tcp|udp", entry_attributes[attr_id]):
                            new_entry.Proto = entry_attributes[attr_id]
                            attr_id += 1
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "source":
                            attr_id += 1
                            if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "eq":
                                attr_id += 1
                                if entry_attributes[attr_id] in L4_PROTO.keys():
                                    entry_attributes[attr_id] = L4_PROTO[entry_attributes[attr_id]]
                                new_entry.SourcePort = entry_attributes[attr_id]
                                attr_id += 1
                            elif attr_id + 1 < len(entry_attributes) and entry_attributes[attr_id] == "range":
                                attr_id += 1
                                new_entry.SourcePortRange = f"{entry_attributes[attr_id]} "\
                                                            f"{entry_attributes[attr_id + 1]}"
                                attr_id += 2
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "eq":
                            attr_id += 1
                            if entry_attributes[attr_id] in L4_PROTO.keys():
                                entry_attributes[attr_id] = L4_PROTO[entry_attributes[attr_id]]
                            new_entry.DestPort = entry_attributes[attr_id]
                            attr_id += 1
                        elif attr_id + 1 < len(entry_attributes) and entry_attributes[attr_id] == "range":
                            attr_id += 1
                            new_entry.DestPortRange = f"{entry_attributes[attr_id]} " \
                                                        f"{entry_attributes[attr_id + 1]}"
                            attr_id += 2

                        logger.debug(f"Object group entry {new_entry}")
                        new_obj.Entries.append(new_entry)
                    else:
                        logger.info(f"Unable to parse entry")
            self.ObjectGroups.append(new_obj)

    def ParseAclFromFile(self, file_name):
        conf = CiscoConfParse(file_name)
        acls = conf.find_objects("^ip access-list")
        logger.debug('Parsing ACLs')
        for acl in acls:
            logger.debug(f"Parsing acl {acl.text}")
            acl_attributes = re.search("^ip access-list (\S+) (\S+)", acl.text)
            acl_type = acl_attributes[1]
            if acl_attributes[2].isdigit():
                acl_name = f"Number_{acl_attributes[2]}"
            else:
                acl_name = acl_attributes[2]
            if acl_type == "standard":
                acl_type_id = ACL_BASIC
            elif acl_type == "extended":
                acl_type_id = ACL_EXTENDED
            else:
                logger.info(f"Unknown acl type")
                continue
            new_acl = Acl(Type=acl_type_id, Name=acl_name)
            for entry in acl.all_children:
                logger.debug(f"Parsing acl entry {entry.text}")
                if acl_type_id == ACL_BASIC:
                    #  10 permit 10.129.42.144 0.0.0.15
                    logger.debug(f"Basic entry")
                    parsed = False
                    entry_attributes = re.search("(\S+) (\S+) (\S+) (\S+)", entry.text)
                    if not parsed and entry_attributes:
                        entry_number = entry_attributes[1]
                        entry_action = entry_attributes[2]
                        if entry_attributes[3] == "host":
                            new_entry = AclL3Entry(Num=entry_number, SourceHost=entry_attributes[4], \
                                                   Action=entry_action)
                        elif entry_attributes[3] == "any":
                            new_entry = AclL3Entry(Num=entry_number, SourceAny=True, \
                                                   Action=entry_action)
                        else:
                            new_entry = AclL3Entry(Num=entry_number, SourceHost=entry_attributes[3], \
                                                   SourceMask=entry_attributes[4], Action=entry_action)
                        new_acl.Entries.append(new_entry)
                        parsed = True
                    entry_attributes = re.search("(\S+) (\S+) (\S+)", entry.text)
                    if not parsed and entry_attributes:
                        logger.debug(f"Parsing basic entry with single IP")
                        entry_number = entry_attributes[1]
                        entry_action = entry_attributes[2]
                        new_entry = AclL3Entry(Num=entry_number, SourceHost=entry_attributes[3], \
                                               Action=entry_action)
                        new_acl.Entries.append(new_entry)
                    if not parsed:
                        logger.info(f"Wildcard for basic entry doesn't work")

                elif acl_type_id == ACL_EXTENDED:
                    #  80 permit object-group AD_Ports_DST any object-group AD_ATM
                    #  90 permit tcp any host 10.1.2.10 eq 5500
                    #  40 permit 112 any host 224.0.0.18
                    #  50 remark *** wug-co + wug-co-r + wug-poller***
                    logger.info("Extended Entry")
                    entry_attributes = re.search("^ (\d+) remark (.*)", entry.text)
                    # remark
                    if entry_attributes:
                        logger.debug("Remark entry")
                        new_entry = AclL3Entry(Num=entry_attributes[1], Remark=entry_attributes[2])
                    # extended entry
                    else:
                        entry_attributes = re.split(r'\s{1,}', entry.text[1:])
                        logger.debug(f"Parsing extended entry {entry_attributes}")
                        # Entry number and entry action
                        new_entry = AclL3Entry(Num=entry_attributes[0], Action=entry_attributes[1])
                        attr_id = 2
                        # Protocol
                        if re.match("tcp|ip|udp|icmp|\d+|esp|gre", entry_attributes[attr_id]):
                            if entry_attributes[attr_id] in L3_PROTO.keys():
                                entry_attributes[attr_id] = L3_PROTO[entry_attributes[attr_id]]
                            new_entry.Proto = entry_attributes[attr_id]
                            logger.debug(f"Protocol {new_entry.Proto}")
                            attr_id += 1
                        # Source attributes
                        source_ip = False
                        # Object groups
                        logger.debug("Parsing source attributes")
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "object-group":
                            attr_id += 1
                            obj_group_name = entry_attributes[attr_id]
                            attr_id += 1
                            if new_entry.Proto and re.match("tcp|udp", new_entry.Proto):
                                new_entry.SourceObject = obj_group_name
                                source_ip = True
                            else:
                                new_entry.SourcePortObject = obj_group_name
                        #
                        if not source_ip and attr_id < len(entry_attributes) and \
                                entry_attributes[attr_id] == "object-group":
                            attr_id += 1
                            new_entry.SourceObject = entry_attributes[attr_id]
                            source_ip = True
                            attr_id += 1
                        # Any
                        if not source_ip and \
                                attr_id < len(entry_attributes) and entry_attributes[attr_id] == "any":
                            new_entry.SourceAny = True
                            source_ip = True
                            attr_id += 1
                        # Host
                        if not source_ip and \
                                attr_id < len(entry_attributes) and entry_attributes[attr_id] == "host":
                            attr_id += 1
                            new_entry.SourceHost = entry_attributes[attr_id]
                            attr_id += 1
                            source_ip = True
                        # IP/Mask
                        if not source_ip and attr_id + 1 < len(entry_attributes) and \
                                re.match("^((\d{1,3}\.){1,3}\*|(\d{1,3}\.){3}\d{1,3})$", \
                                         entry_attributes[attr_id]) and \
                                re.match("^((\d{1,3}\.){1,3}\*|(\d{1,3}\.){3}\d{1,3})$", \
                                         entry_attributes[attr_id + 1]):
                            new_entry.SourceIP = entry_attributes[attr_id]
                            attr_id += 1
                            new_entry.SourceMask = entry_attributes[attr_id]
                            attr_id += 1
                            source_ip = True
                        # Port
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "eq":
                            attr_id += 1
                            if entry_attributes[attr_id] in L4_PROTO.keys():
                                entry_attributes[attr_id] = L4_PROTO[entry_attributes[attr_id]]
                            new_entry.SourcePort = entry_attributes[attr_id]
                            attr_id += 1
                            while attr_id < len(entry_attributes) and re.match("^\d+$", entry_attributes[attr_id]):
                                if entry_attributes[attr_id] in L4_PROTO.keys():
                                    entry_attributes[attr_id] = L4_PROTO[entry_attributes[attr_id]]
                                new_entry.SourcePort += f" {entry_attributes[attr_id]}"
                                attr_id += 1
                        # Port Range
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "range":
                            attr_id += 1
                            new_entry.SourcePortRange = f"{entry_attributes[attr_id]} {entry_attributes[attr_id + 1]}"
                            attr_id += 2

                        # Destination attributes
                        logger.debug("Parsing dest attributes")
                        # Object groups
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "object-group":
                            attr_id += 1
                            obj_group_name = entry_attributes[attr_id]
                            attr_id += 1
                            new_entry.DestObject = obj_group_name
                        # Any
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "any":
                            new_entry.DestAny = True
                            attr_id += 1
                        # Host
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "host":
                            attr_id += 1
                            new_entry.DestHost = entry_attributes[attr_id]
                            attr_id += 1
                        # IP/Mask
                        if attr_id + 1 < len(entry_attributes) and \
                                re.match("^((\d{1,3}\.){1,3}\*|(\d{1,3}\.){3}\d{1,3})$", \
                                         entry_attributes[attr_id]) and \
                                re.match("^((\d{1,3}\.){1,3}\*|(\d{1,3}\.){3}\d{1,3})$", \
                                         entry_attributes[attr_id + 1]):
                            new_entry.DestIP = entry_attributes[attr_id]
                            attr_id += 1
                            new_entry.DestMask = entry_attributes[attr_id]
                            attr_id += 1
                        # Port
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "eq":
                            attr_id += 1
                            if entry_attributes[attr_id] in L4_PROTO.keys():
                                entry_attributes[attr_id] = L4_PROTO[entry_attributes[attr_id]]
                            new_entry.DestPort = entry_attributes[attr_id]
                            attr_id += 1
                            while attr_id < len(entry_attributes) and  re.match("^\d+$", entry_attributes[attr_id]):
                                if entry_attributes[attr_id] in L4_PROTO.keys():
                                    entry_attributes[attr_id] = L4_PROTO[entry_attributes[attr_id]]
                                new_entry.DestPort += f" {entry_attributes[attr_id]}"
                                attr_id += 1
                        # Port Range
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "range":
                            attr_id += 1
                            new_entry.DestPortRange = f"{entry_attributes[attr_id]} {entry_attributes[attr_id + 1]}"
                            attr_id += 2

                        # Time Range
                        if attr_id < len(entry_attributes) and entry_attributes[attr_id] == "time-range":
                            attr_id += 1
                            new_entry.TimeRange = entry_attributes[attr_id]
                            attr_id += 1

                        # Additional attributes
                        if attr_id < len(entry_attributes) and re.match("echo|echo-reply", entry_attributes[attr_id]):
                            new_entry.ICMPType = entry_attributes[attr_id]
                            attr_id += 1

                    logger.debug(f"ACL entry - {new_entry}")
                    new_acl.Entries.append(new_entry)

            self.ACLs.append(new_acl)

    def ParseConfigFromFile(self, file_name):
        logger.debug(f"Parsing Cisco config file {file_name}")
        self.ParseObjectGroupsFromFile(file_name)
        self.ParseAclFromFile(file_name)

