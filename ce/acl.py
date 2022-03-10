from datetime import datetime
from typing import List, Optional, Union
from pydantic import BaseModel


ACL_BASIC = 1
ACL_EXTENDED = 2

ACL_ACTION_ACCEPT = 1
ACL_ACTION_DENY = 2

OBJ_NETWORK = 1
OBJ_SERVICE = 2

L4_PROTO = {
    'msrpc': "135",
    'ntp':  "123",
    'smtp': "25",
    'domain': "53",
    'isakmp': "500",
    "non500-isakmp": "4500"
}

L3_PROTO = {
    'esp': "50"
}

class ObjectGroupHostEntry(BaseModel):
    Host: Optional[str]
    IPAddress: Optional[str]
    Mask: Optional[str]


class ObjectGroupServiceEntry(BaseModel):
    Proto: Optional[str]
    SourcePort: Optional[str]
    SourcePortRange: Optional[str]
    DestPort: Optional[str]
    DestPortRange: Optional[str]


class ObjectGroup(BaseModel):
    Name: str
    Type: int
    Description: Optional[str]
    Entries: List[Union[ObjectGroupHostEntry, ObjectGroupServiceEntry]] = []


class AclL3Entry(BaseModel):
    Num: int
    Proto: Optional[str]
    SourceAny: Optional[bool]
    SourceHost: Optional[str]
    SourceIP: Optional[str]
    SourceMask: Optional[str]
    SourceObject: Optional[str]
    SourcePort: Optional[str]
    SourcePortRange: Optional[str]
    SourcePortObject: Optional[str]
    DestAny: Optional[bool]
    DestHost: Optional[str]
    DestIP: Optional[str]
    DestMask: Optional[str]
    DestObject: Optional[str]
    DestPort: Optional[str]
    DestPortRange: Optional[str]
    DestPortObject: Optional[str]
    Action: Optional[str]
    TimeRange: Optional[str]
    Remark: Optional[str]
    ICMPType: Optional[str]


class Acl(BaseModel):
    Type: int
    Name: Optional[str]
    Id: Optional[int]
    Entries: List[AclL3Entry] = []



