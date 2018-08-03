# Automatically generated by pb2py
# fmt: off
import protobuf as p

from .HDNodeType import HDNodeType

if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None  # type: ignore


class HDNodePathType(p.MessageType):
    FIELDS = {
        1: ('node', HDNodeType, 0),  # required
        2: ('address_n', p.UVarintType, p.FLAG_REPEATED),
    }

    def __init__(
        self,
        node: HDNodeType = None,
        address_n: List[int] = None,
    ) -> None:
        self.node = node
        self.address_n = address_n if address_n is not None else []
