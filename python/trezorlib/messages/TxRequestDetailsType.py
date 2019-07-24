# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class TxRequestDetailsType(p.MessageType):

    def __init__(
        self,
        request_index: int = None,
        tx_hash: bytes = None,
        extra_data_len: int = None,
        extra_data_offset: int = None,
    ) -> None:
        self.request_index = request_index
        self.tx_hash = tx_hash
        self.extra_data_len = extra_data_len
        self.extra_data_offset = extra_data_offset

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('request_index', p.UVarintType, 0),
            2: ('tx_hash', p.BytesType, 0),
            3: ('extra_data_len', p.UVarintType, 0),
            4: ('extra_data_offset', p.UVarintType, 0),
        }