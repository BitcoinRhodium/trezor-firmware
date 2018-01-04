# Automatically generated by pb2py
from __future__ import absolute_import
from .. import protobuf as p
from .NEMTransfer import NEMTransfer
from .NEMMosaicCreation import NEMMosaicCreation
from .NEMProvisionNamespace import NEMProvisionNamespace
from .NEMImportanceTransfer import NEMImportanceTransfer
from .NEMAggregateModification import NEMAggregateModification
from .NEMMosaicSupplyChange import NEMMosaicSupplyChange
from .NEMTransactionCommon import NEMTransactionCommon


class NEMSignTx(p.MessageType):
    FIELDS = {
        1: ('transaction', NEMTransactionCommon, 0),
        2: ('multisig', NEMTransactionCommon, 0),
        3: ('transfer', NEMTransfer, 0),
        4: ('cosigning', p.BoolType, 0),
        5: ('provision_namespace', NEMProvisionNamespace, 0),
        6: ('mosaic_creation', NEMMosaicCreation, 0),
        7: ('supply_change', NEMMosaicSupplyChange, 0),
        8: ('aggregate_modification', NEMAggregateModification, 0),
        9: ('importance_transfer', NEMImportanceTransfer, 0),
    }
    MESSAGE_WIRE_TYPE = 69