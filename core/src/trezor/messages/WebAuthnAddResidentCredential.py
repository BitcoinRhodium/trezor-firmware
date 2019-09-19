# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import Dict, List, Optional
        from typing_extensions import Literal  # noqa: F401
    except ImportError:
        Dict, List, Optional = None, None, None  # type: ignore


class WebAuthnAddResidentCredential(p.MessageType):
    MESSAGE_WIRE_TYPE = 802

    def __init__(
        self,
        credential_id: bytes = None,
    ) -> None:
        self.credential_id = credential_id

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('credential_id', p.BytesType, 0),
        }
