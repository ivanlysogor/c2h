from helpers import logger
from ce import Acl, AclL3Entry, ACL_BASIC, ACL_EXTENDED, \
    ObjectGroup, ObjectGroupHostEntry, ObjectGroupServiceEntry,  \
    OBJ_SERVICE, OBJ_NETWORK
from .device import NetworkDevice


class HuaweiNetworkDevice(NetworkDevice):

    def GenerateAcl(self):
        for Acl in self.ACLs:
            # Generate header
            if Acl.Name:
                yield f"undo acl name {Acl.Name}"
                yield f"acl name {Acl.Name}"
            else:
                yield f"unacl number {Acl.Id}"
                yield f"acl number {Acl.Id}"
            # Generate lines
            num = 5
            # check for duplicates
            acl_entries = []
            for entry in Acl.Entries:
                # init variables
                source = []
                dest = []
                # check for remarks
                if entry.Remark:
                    yield f" rule {num} description {entry.Remark}"
                    num += 5
                    continue
                # parsing common data
                action = f"{entry.Action}"
                if entry.Proto:
                    proto = entry.Proto
                else:
                    proto = "ip"
                # parsing source
                if entry.SourceObject:
                    obj = self.GetObjectGroup(entry.SourceObject)
                    if obj and obj.Type == OBJ_NETWORK:
                        for host in obj.Entries:
                            if host.Host:
                                source.append(f"source {host.Host} 0")
                            else:
                                source.append(f"source {host.IPAddress} {host.Mask}")
                    else:
                        logger.info(f"Unable to find object-group {entry.SourceObject}")
                if entry.SourceAny:
                    source.append(f"source any")
                elif entry.SourceHost:
                    source.append(f"source {entry.SourceHost} 0")
                elif entry.SourceIP and entry.SourceMask:
                    source.append(f"source {entry.SourceIP} {entry.SourceMask}")

                # source Port
                source_port = []
                dest_port = []
                source_port_group = False

                if entry.SourcePort:
                    for p in entry.SourcePort.split(" "):
                        source_port.append([proto, f" source-port eq {p}"])
                elif entry.SourcePortRange:
                    source_port.append([proto, f" source-port range {entry.SourcePortRange}"])
                elif entry.SourcePortObject:
                    # Parsing port Object
                    PortObject = self.GetObjectGroup(entry.SourcePortObject)
                    if PortObject and PortObject.Type == OBJ_SERVICE:
                        og_source = []
                        og_dest = []
                        for Port in PortObject.Entries:
                            if Port.SourcePort:
                                source_port.append([Port.Proto, f"source-port eq {Port.SourcePort}"])
                            elif Port.SourcePortRange:
                                source_port.append([Port.Proto, f"source-port range {Port.SourcePortRange}"])
                            elif len(og_source) == 0:
                                source_port.append([Port.Proto, ""])

                            if Port.DestPort:
                                dest_port.append([Port.Proto, f"destination-port eq {Port.DestPort}"])
                            elif Port.DestPortRange:
                                dest_port.append([Port.Proto, f"destination-port range {Port.DestPortRange}"])
                            elif len(dest_port) == 0:
                                dest_port.append([Port.Proto, ""])
                        source_port_group = True
                    else:
                        logger.info(f"Unable to get Port Object {entry.SourcePortObject}")
                else:
                    source_port.append([proto, ""])

                #parsing destination
                if entry.DestObject:
                    obj = self.GetObjectGroup(entry.DestObject)
                    if obj and obj.Type == OBJ_NETWORK:
                        for host in obj.Entries:
                            if host.Host:
                                dest.append(f"destination {host.Host} 0")
                            else:
                                dest.append(f"destination {host.IPAddress} {host.Mask}")
                    else:
                        logger.info(f"Unable to find object-group {entry.SourceObject}")
                if entry.DestAny or Acl.Type == ACL_BASIC:
                    dest.append("destination any")
                if entry.DestHost:
                    dest.append(f"destination {entry.DestHost} 0")
                if entry.DestIP and entry.DestMask:
                    dest.append(f"destination {entry.DestIP} {entry.DestMask}")

                if not source_port_group and entry.DestPort:
                    for p in entry.DestPort.split(" "):
                        dest_port.append([proto, f" destination-port eq {p}"])
                elif not source_port_group and entry.DestPortRange:
                    dest_port.append([proto, f" destination-port range {entry.DestPortRange}"])
                elif not source_port_group:
                    dest_port.append([proto, ""])
                # additional data
                additional = ""
                if entry.Proto == "icmp" and entry.ICMPType:
                    additional += f"icmp-type {entry.ICMPType}"
                for s in source:
                    for sp in source_port:
                        for d in dest:
                            for dp in dest_port:
                                if (sp[0] == "tcp-udp") or dp[0] == ("tcp-tcp") or \
                                        (sp[0] == "tcp" and dp[0] == "udp") or \
                                        (dp[0] == "tcp" and sp[0] == "udp"):
                                    proto = ['tcp','udp']
                                else:
                                    proto = [sp[0]]
                                for p in proto:
                                    rule = f"{action} {p} {s} {sp[1]} {d} {dp[1]} {additional}"
                                    if rule not in acl_entries:
                                        yield f" rule {num} {rule}"
                                        num += 5
                                        acl_entries.append(rule)

            yield f"quit"
