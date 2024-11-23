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

class Send_RR_Data_Request(Structure):
    """
    Send RR Data request structure with static fields.
    Dynamically parses items using a helper method.
    """
    _pack_ = 1
    _fields_ = [
        ('interface_handle', c_uint32),  # Interface handle (4 bytes, 0 for CIP)
        ('timeout', c_uint16),          # Timeout in ms
        ('item_count', c_uint16),       # Number of items (typically 2)
    ]

    def __init__(self, data):
        """
        Initialize the structure and parse items.
        :param data: The raw request bytes.
        """
        super().__init__()
        memmove(addressof(self), data, sizeof(self))
        # Dynamically parse the items
        self.items = self._parse_items(data[sizeof(self):])
        self.generate_response()

    def _parse_items(self, items_data):
        """
        Parse the dynamic items and return a list of item objects.
        :param items_data: The raw data containing the items.
        :return: List of parsed item objects.
        """
        CIP_items = {
            0x0000: NullAddressItem,
            0x00B2: UnconnectedDataItem,
            0x0000: SocketAddressInfo,

        }
        offset = 0
        items = []
        for _ in range(self.item_count):
            # Parse item header (Type ID and Length)
            item_type, item_length = struct.unpack_from('<HH', items_data, offset)
            offset += sizeof(c_uint16)+sizeof(c_uint16) # Type Id and Length each 2 bytes
            # Extract item data
            item_data = items_data[offset:offset + item_length]
            offset += item_length
            if item_type not in CIP_items:
                raise ValueError(f"Unsupported CIP Item: 0x{item_type:04X}")
            items.append(CIP_items[item_type](item_data))
        return items


class Send_RR_Data_Response(Structure):
    """
    Represents the Send RR Data Response with dynamically determined items.
    """
    _pack_ = 1
    _fields_ = [
        ('interface_handle', c_uint32),  # Interface handle
        ('timeout', c_uint16),          # Timeout
        ('item_count', c_uint16),       # Number of items
    ]

    def __init__(self, request_items, cip_response_data, socket_info):
        """
        Initialize the response based on the request items and other inputs.
        :param request_items: Parsed items from the request.
        :param cip_response_data: Data to include in the Unconnected Data Item.
        :param socket_info: Data for the Socket Address Info Item.
        """
        super().__init__()
        self.interface_handle = 0  # Typically 0 for CIP
        self.timeout = 0           # Typically 0
        self.items = []

        # Always include Null Address Item if present in request
        if any(isinstance(item, NullAddressItem) for item in request_items):
            self.items.append(NullAddressItem())

        # Add the Unconnected Data Item
        self.items.append(UnconnectedDataItem(cip_response_data))

        # Add the Socket Address Info Item if socket information is provided
        if socket_info:
            self.items.append(SocketAddressInfo(socket_info))

        # Set the item count
        self.item_count = len(self.items)

    def to_bytes(self):
        """
        Convert the response to bytes.
        """
        static_part = bytes(self)
        dynamic_part = b''.join(item.to_bytes() for item in self.items)
        return static_part + dynamic_part





class CIP_IO_Reply(Structure):
    """Cyclic IO reply structure."""
    _pack_ = 1
    _fields_ = [
        ('item_count', c_uint32),  # Item Count
        ('type1_id', c_uint16),     # Type ID
        ('type1_len', c_uint16),      # Length of Data Item (CIP payload length)
        ('connection_id', c_uint32),
        ('encap_seq_count', c_uint32),
        ('type2_id', c_uint16),     # Type ID
        ('type2_len', c_uint16),      # Length of Data Item (CIP payload length)
        ('cip_seq_count', c_uint16)    
    ]