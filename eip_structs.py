from ctypes import *
import logging
import struct
from cip_service_structs import (
    GetAttributeSingleData,
    SetAttributeSingleData,
    ForwardCloseData,
    ReadTagServiceData,
    WriteTagServiceData,
    UnconnectedSendData,
    NullAddressItem,
    UnconnectedDataItem,
    SocketAddressInfo

)

def hex_escape(data):
    """Convert binary data to a string of escaped hexadecimal byte values."""
    if data:
        return ''.join([r'\x{:02x}'.format(b) for b in data])

def set_from_buffer(Struct, data):
    """Utility function to create a structure instance from raw buffer data."""
    return Struct.from_buffer(bytearray(data))

def parse_param_data(service, param_data):
    """Parse the `param_data` field based on the CIP service code."""
    service_parsers = {
        0x0E: GetAttributeSingleData,  # Get Attribute Single
        0x10: SetAttributeSingleData,  # Set Attribute Single
        #0x54: ForwardOpenData,         # Forward Open
        0x4E: ForwardCloseData,        # Forward Close
        0x4C: ReadTagServiceData,      # Read Tag Service
        0x4D: WriteTagServiceData,     # Write Tag Service
        0x52: UnconnectedSendData,     # Unconnected Send
    }

    if service not in service_parsers:
        raise ValueError(f"Unsupported CIP service: 0x{service:02X}")

    structure_class = service_parsers[service]
    return structure_class.from_buffer_copy(param_data)

class EIP_Header(Structure):
    """EtherNet/IP header structure."""
    _pack_ = 1
    _fields_ = [
        ('cmd', c_uint16),
        ('len', c_uint16),
        ('session_handle', c_uint32),
        ('status', c_uint32),
        ('sender_context', c_uint64),
        ('options', c_uint32),
    ]

class Send_RR_Data(Structure):
    """
    Represents the Send RR Data structure for requests and responses.
    """
    _pack_ = 1
    _fields_ = [
        ('interface_handle', c_uint32),  # Interface handle
        ('timeout', c_uint16),          # Timeout
        ('item_count', c_uint16),       # Number of items
    ]

    def __init__(self, data=None):
        """
        Initialize the structure, optionally parsing data into items.
        :param data: Raw data to parse (for requests), or None for empty response.
        """
        super().__init__()
        self.interface_handle = 0  # Default to 0
        self.timeout = 0           # Default to 0
        self.items = []            # Dynamic list of items

        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))
            self._parse_items(data)

    def _parse_items(self, data):
        """
        Parse items from raw data and populate self.items.
        :param data: Raw data containing item information.
        """
        offset = sizeof(Send_RR_Data)  # Start after the fixed fields
        for _ in range(self.item_count):
            # Read item type and length
            item_type, item_len = struct.unpack_from('<HH', data, offset)
            offset += 4  # Advance past type and length
            item_data = data[offset:offset + item_len]
            offset += item_len

            # Create the appropriate item and add it
            self.add_item(self.create_item(item_type, item_data))

    def create_item(self, item_type, item_data=None):
        """
        Factory method to create item instances based on type.
        :param item_type: Item type identifier.
        :param item_data: Raw item data.
        :return: An instance of the corresponding item class.
        """
        if item_type == NullAddressItem.type_code:  # Null Address Item
            return NullAddressItem()
        elif item_type == UnconnectedDataItem.type_code:  # Unconnected Data Item
            return UnconnectedDataItem(item_data)
        elif item_type == SocketAddressInfo.type_code:  # Socket Address Info Item
            return SocketAddressInfo(item_data)
        else:
            raise ValueError(f"Unknown item type: 0x{item_type:04X}")

    def add_item(self, item):
        """
        Add an item to the structure.
        :param item: Instance of an item class (e.g., NullAddressItem).
        """
        self.items.append(item)
        self.item_count = len(self.items)  # Update the item count dynamically

    def to_bytes(self):
        """
        Serialize the structure and its items into bytes.
        :return: Serialized data as bytes.
        """
        base = bytes(self)  # Fixed fields
        items_data = b''.join(item.to_bytes() for item in self.items)
        return base + items_data



class CIP_IO_Reply(Structure):
    """Cyclic IO reply structure."""
    _pack_ = 1
    _fields_ = [
        ('item_count', c_uint16),  # Item Count
        ('type1_id', c_uint16),     # Type ID
        ('type1_len', c_uint16),      # Length of Data Item (CIP payload length)
        ('connection_id', c_uint32),
        ('encap_seq_count', c_uint32),
        ('type2_id', c_uint16),     # Type ID
        ('type2_len', c_uint16),      # Length of Data Item (CIP payload length)
        ('cip_seq_count', c_uint16)    
    ]

    def __init__(self, connection_id, sequence, io_data) -> None:
        self.item_count = 2
        self.type1_id = 0x8002 #Sequenced Address Item
        self.type1_len =  8
        if connection_id:
            self.connection_id = connection_id
        self.encap_seq_count = sequence
        
        self.type2_id = 0x00b1 #Connected Data Item
        self.type2_len =  len(io_data)
        self.cip_seq_count = sequence & 0xFFFF
        self.io_data = io_data

    def to_bytes(self):
        return bytes(self) + self.io_data