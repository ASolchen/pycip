from ctypes import *
import logging
from cip_service_structs import (
    GetAttributeSingleData,
    SetAttributeSingleData,
    ForwardCloseData,
    ReadTagServiceData,
    WriteTagServiceData,
    UnconnectedSendData
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
    """Send RR Data request structure."""
    _pack_ = 1
    _fields_ = [
        ('interface_handle', c_uint32),  # Interface handle (4 bytes, 0 for CIP)
        ('timeout', c_uint16),          # Timeout in ms
        ('item_count', c_uint16),       # Number of items (typically 2)

        # Address Item
        ('item0_type_id', c_uint16),    # Type ID for Address Item
        ('item0_len', c_uint16),        # Length of Address Item (0 for null address)

        # Data Item
        ('item1_type_id', c_uint16),    # Type ID for Data Item (0x00B2 for unconnected)
        ('item1_len', c_uint16),        # Length of Data Item
    ]

    def get_paramxxx_data(self):
        """Extract actual parameter data up to `item1_len`."""
        return bytes(self.param_data[:self.item1_len])


class Send_RR_Data_Reply(Structure):
    """Send RR Data reply structure."""
    _pack_ = 1
    _fields_ = [
        ('interface_handle', c_uint32),
        ('timeout', c_uint16),
        ('item_count', c_uint16),
        ('item0_type_id', c_uint16),
        ('item0_len', c_uint16),
        ('item1_type_id', c_uint16),
        ('item1_len', c_uint16),
        ('service', c_uint8),
        ('reserved', c_uint8),
        ('path_size', c_uint8),
        ('path_class', c_uint8),
        ('path_instance', c_uint16),
        ('cip_data', c_uint8 * 30),
    ]


