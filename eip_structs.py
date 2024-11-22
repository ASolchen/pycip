from ctypes import *
import socket
import logging
import binascii
from cip_service_structs import GetAttributeSingleData, SetAttributeSingleData, \
                            ForwardOpenData, ForwardCloseData, ReadTagServiceData, \
                            WriteTagServiceData, UnconnectedSendData
def hex_escape(data):
    if data:
        """Convert binary data to a string of escaped hexadecimal byte values."""
        return ''.join([r'\x{:02x}'.format(b) for b in data])

def set_from_buffer(Struct, data):
    """from escaped string"""
    return Struct.from_buffer(bytearray(data))

def parse_param_data(service, param_data):
    """
    Parses the `param_data` field of a CIP message based on the service code.
    
    :param service: The CIP service code (e.g., 0x0E for Get Attribute Single).
    :param param_data: The binary data to parse.
    :return: An instance of the appropriate CIP structure.
    :raises ValueError: If the service code is unsupported.
    """
    # Dictionary mapping service codes to structure classes
    service_parsers = {
        0x0E: GetAttributeSingleData,  # Get Attribute Single
        0x10: SetAttributeSingleData,  # Set Attribute Single
        0x54: ForwardOpenData,         # Forward Open
        0x4E: ForwardCloseData,        # Forward Close
        0x4C: ReadTagServiceData,      # Read Tag Service
        0x4D: WriteTagServiceData,     # Write Tag Service
        0x52: UnconnectedSendData,     # Unconnected Send
        # Add other services as needed
    }

    # Check if the service is supported
    if service not in service_parsers:
        raise ValueError(f"Unsupported CIP service: 0x{service:02X}")

    # Parse the param_data using the appropriate structure class
    structure_class = service_parsers[service]
    return structure_class.from_buffer_copy(param_data)


class EIP_Header(Structure):
    """24 bytes"""
    _pack_ = 1
    _fields_ =  [
        ('cmd', c_uint16),
        ('len', c_uint16),
        ('session_handle', c_uint32),
        ('status', c_uint32),
        ('sender_context', c_uint64),
        ('options', c_uint32),
        ]

class CIP_List_Services_Reply(Structure):
    """26 bytes"""
    _pack_ = 1
    _fields_ =  [
        ('item_count', c_uint16),
        ('type_id', c_uint16),
        ('len', c_uint16),
        ('encapaver', c_uint16),
        ('capaflags', c_uint16),
        ('servicename', c_char * 16),
        ]

class Register_Session_Reply(Structure):
    """adapter returns a session handle to the scanner to verify the session is registered"""
    """4 bytes"""
    _pack_ = 1
    _fields_ = [
        ('version', c_uint16),
        ('flags', c_uint16),
    ]

class Send_RR_Data_Request(Structure):
    """Structure for Send RR Data request"""
    _pack_ = 1
    _fields_ = [
        ('interface_handle', c_uint32),       # Always 0 for CIP
        ('timeout', c_uint16),               # Timeout in ms
        ('item_count', c_uint16),            # Number of items (typically 2 or 3)

        # Address Item
        ('item0_type_id', c_uint16),         # Address Item Type (0x0000 = Null)
        ('item0_len', c_uint16),             # Address Item Length (0)

        # Data Item
        ('item1_type_id', c_uint16),         # Data Item Type (0x00B2 = Unconnected Data)
        ('item1_len', c_uint16),             # Data Item Length (CIP data length)

        # CIP Request Header
        ('service', c_uint8),                # CIP Service Code (e.g., 0x54 = Forward Open)
        ('reserved', c_uint8),               # Reserved field
        ('path_size', c_uint8),              # Logical Path size in 16-bit words
        ('path_class', c_uint8),             # Path Class
        ('path_instance', c_uint16),         # Path Instance

        # CIP Parameters
        ('o_t_rpi', c_uint32),               # O->T Requested Packet Interval
        ('o_t_connection_id', c_uint32),    # O->T Connection ID
        ('t_o_connection_id', c_uint32),    # T->O Connection ID
        ('o_t_network_params', c_uint16),   # O->T Network Parameters
        ('t_o_network_params', c_uint16),   # T->O Network Parameters
        ('transport_type', c_uint8),        # Transport Type/Trigger
        ('connection_path_size', c_uint8),  # Connection Path size
        ('param_data', c_uint8 * 512),      # Buffer for variable-length data
    ]

    def get_param_data(self):
        """Extract the actual param_data up to item1_len."""
        return bytes(self.param_data[:self.item1_len])

class Send_RR_Data_Reply(Structure):
    """Structure for Send RR Data reply"""
    _pack_ = 1
    _fields_ = [
        # Ethernet/IP Encapsulation
        ('interface_handle', c_uint32),       # Interface Handle (0 for CIP)
        ('timeout', c_uint16),               # Timeout in ms
        ('item_count', c_uint16),            # Number of items (2 or 3)

        # Address Item (Null Address)
        ('item0_type_id', c_uint16),         # Type ID (0x0000 for Null)
        ('item0_len', c_uint16),             # Length (0 for Null)

        # Data Item (Unconnected Data)
        ('item1_type_id', c_uint16),         # Type ID (0x00B2 for Unconnected Data)
        ('item1_len', c_uint16),             # Length of CIP Data

        # CIP Response Data (Variable Length)
        ('service', c_uint8),                # CIP Service Response Code
        ('reserved', c_uint8),               # Reserved/Padding
        ('path_size', c_uint8),              # Path size in 16-bit words
        ('path_class', c_uint8),             # Path: Class
        ('path_instance', c_uint16),         # Path: Instance
        ('cip_data', c_uint8 * 30),          # CIP Data (length varies)
    ]


