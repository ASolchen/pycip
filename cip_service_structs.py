from ctypes import *
import logging
import struct


from ctypes import Structure, c_uint8
from cip_item_structs import NullAddressItem, UnconnectedDataItem, SocketAddressInfo  # Example item classes

class CIP_Message(Structure):
    """
    CIP Message structure for service-specific data.
    Can represent both requests and responses.
    """
    _pack_ = 1
    _fields_ = [
        ('service', c_uint8),           # Service Code (with reply bit set for responses)
        ('reserved', c_uint8),          # Reserved byte (0x00 for requests, often unused in replies)
        ('general_status', c_uint8),    # General status (0x00 = success)
        ('additional_status_size', c_uint8),  # Size of additional status in words
    ]

    def __init__(self, data=None):
        """
        Initialize the CIP Message and parse items from the data.
        :param data: Raw CIP message data (bytes)
        """
        super().__init__()
        self.items = []
        # Parse fixed fields
        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))
            # Extract items
            self._parse_items(data[sizeof(self):])

    def _parse_items(self, data):
        """
        Parse dynamic items from the raw data.
        :param data: Raw data following the fixed fields
        """
        offset = 0
        while offset < len(data):
            # Extract item type and length
            item_type, item_len = struct.unpack_from('<HH', data, offset)
            offset += 4
            item_data = data[offset:offset + item_len]
            offset += item_len

            # Add items based on type
            if item_type == 0x0000:  # Null Address Item
                self.items.append(NullAddressItem(item_data))
            elif item_type == 0x00B2:  # Unconnected Data Item
                self.items.append(UnconnectedDataItem(item_data))
            elif item_type == 0x8000:  # Socket Address Info
                self.items.append(SocketAddressInfo(item_data))
            else:
                logging.warning(f"Unknown item type: 0x{item_type:04X}")

    def to_bytes(self):
        """
        Serialize the CIP Message, including items.
        :return: Serialized CIP Message
        """
        base = bytes(self)
        items_data = b''.join(item.to_bytes() for item in self.items)
        return base + items_data




class ForwardOpenRequest(Structure):
    """
    CIP Forward Open Request structure based on CIP Table 3-5.16.
    Updated to account for segment fields and proper alignment.
    """
    _pack_ = 1
    _fields_ = [
        
        # Unconnected Data Item Header
        ('type_is', c_uint16),            # Service code (0x0062 = Unconnected Data Item)
        ('length', c_uint16),             # Length in bytes

        # CIP Header
        ('service', c_uint8),            # Service code (0x54 = Forward Open)
        ('req_path_size', c_uint8),      # Request Path Size in words (2 Words)

        # Class Segment (Logical Segment)
        ('class_segment_format', c_uint8, 2),  # Logical Format (0)
        ('class_segment_type', c_uint8, 3),    # Logical Type (0x01 for Class ID)
        ('class_path_segment', c_uint8, 3),    # Path Segment (Type 1)
        ('class', c_uint8),                    # Class number (0x06 = Connection Manager)

        # Instance Segment (Logical Segment)
        ('instance_segment_format', c_uint8, 2),  # Logical Format (0)
        ('instance_segment_type', c_uint8, 3),    # Logical Type (0x01 for Instance ID)
        ('instance_path_segment', c_uint8, 3),    # Path Segment (Type 1)
        ('instance', c_uint8),                   # Instance number (0x01)

        # Connection Parameters
        ('tick_time', c_uint8, 4),              # Timeout Ticks (4 bits)
        ('priority', c_uint8, 1),               # Priority (1 bit)
        ('reserved_01', c_uint8, 3),            # Reserved (3 bits)
        ('time_out_ticks', c_uint8),            # Timeout Ticks

        ('o_t_connection_id', c_uint32),        # O->T Connection ID
        ('t_o_connection_id', c_uint32),        # T->O Connection ID

        ('connection_serial_number', c_uint16), # Connection Serial Number
        ('originator_vendor_id', c_uint16),     # Vendor ID
        ('originator_serial_number', c_uint32), # Originator Serial Number

        ('connection_to_multiplier', c_uint8),  # Connection Timeout Multiplier
        ('reserved_02', c_uint8 * 3),           # Reserved

        ('o_t_rpi', c_uint32),                  # O->T Requested Packet Interval (RPI)
        ('o_t_network_params', c_uint16),       # O->T Network Parameters
        ('t_o_rpi', c_uint32),                  # T->O Requested Packet Interval (RPI)
        ('t_o_network_params', c_uint16),       # T->O Network Parameters

        ('transport_type', c_uint8),            # Transport Type/Trigger
        ('connection_path_size', c_uint8),      # Connection Path Size (in words)

        # Connection Path
        ('connection_path', c_uint8 * 40),      # Encoded Path (variable length, max 40 bytes)
    ]

    def __init__(self, data=None):
        """
        Initialize the structure from raw data or set defaults.
        """
        super().__init__()
        if data:
            # Copy raw data into the structure
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))
        else:
            # Set default values
            self.service = 0x54  # Forward Open

    def to_bytes(self):
        """
        Convert the structure to bytes for serialization.
        Automatically calculates the length field.
        """
        self.length = len(bytes(self)) - 4  # Exclude the initial fields
        return bytes(self)



#TODO fix response

class ForwardOpenResponse(Structure):
    _pack_ = 1
    _fields_ = [
        ('service', c_uint8),  # 0x54 with response bit set
        ('reserved_01', c_uint8 * 3),   # Reserved
        ('o_t_connection_id', c_uint32),    # O->T Connection ID
        ('t_o_connection_id', c_uint32),    # T->O Connection ID
        ('connection_serial_number', c_uint16), # Connection Serial Number 
        ('originator_vendor_id', c_uint16), # Originator Vendor ID
        ('originator_serial_number', c_uint32), # Originator Serial Number 
        ('o_t_rpi', c_uint32),              # T->O RPI
        ('t_o_rpi', c_uint32),              # T->O RPI
        ('application_reply_size', c_uint8),   # Application Reply Size (zero?)
        ('reserved_02', c_uint8),   # Reserved
    ]
    
    def __init__(self, data=None):
        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))
        self.service = 0x54 | 0x80
    
    def to_bytes(self):
        """Convert to bytes."""
        self.length = len(bytes(self))
        return bytes(self)

class ForwardCloseData(Structure):
    """CIP: Forward Close (0x4E)"""
    _pack_ = 1
    _fields_ = [
        ('priority_tick', c_uint16),         # Priority and Time Tick
        ('timeout_ticks', c_uint8),         # Timeout Ticks
        ('connection_serial', c_uint16),    # Connection Serial Number
        ('vendor_id', c_uint16),            # Vendor ID
        ('originator_serial', c_uint32),    # Originator Serial Number
        ('connection_path_size', c_uint8),  # Connection Path Size
        ('path', c_uint16 * 4),             # Logical Path (size varies)
    ]
    def __init__(self, data=None):
        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))

class GetAttributeSingleData(Structure):
    _pack_ = 1
    _fields_ = [
        ('class_id', c_uint8),             # Object Class
        ('instance_id', c_uint8),          # Object Instance
        ('attribute_id', c_uint8),         # Attribute ID
    ]
    def __init__(self, data=None):
        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))

class SetAttributeSingleData(Structure):
    """CIP: Set Attribute Single (0x10)"""
    _pack_ = 1
    _fields_ = [
        ('class_id', c_uint8),             # Object Class
        ('instance_id', c_uint8),          # Object Instance
        ('attribute_id', c_uint8),         # Attribute ID
        ('data_length', c_uint16),         # Length of the data
        ('data', c_uint8 * 256),           # Buffer for data (length based on `data_length`)
    ]
    def __init__(self, data=None):
        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))

class ResetData(Structure):
    """CIP: Reset (0x05)"""
    _pack_ = 1
    _fields_ = [
        ('reset_type', c_uint8),           # Reset Type (0x00 = Soft Reset, 0x01 = Hard Reset)
    ]
    def __init__(self, data=None):
        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))

class ReadTagServiceData(Structure):
    """CIP: Read Tag Service (0x4C)"""
    _pack_ = 1
    _fields_ = [
        ('tag_name_length', c_uint16),     # Length of the tag name
        ('tag_name', c_char * 64),         # Tag name (null-terminated string)
        ('offset', c_uint32),              # Offset (used for arrays)
        ('element_count', c_uint16),       # Number of elements to read
    ]
    def __init__(self, data=None):
        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))

class WriteTagServiceData(Structure):
    """CIP: Write Tag Service (0x4D)"""
    _pack_ = 1
    _fields_ = [
        ('tag_name_length', c_uint16),     # Length of the tag name
        ('tag_name', c_char * 64),         # Tag name (null-terminated string)
        ('offset', c_uint32),              # Offset (used for arrays)
        ('data_type', c_uint16),           # Data type of the tag
        ('element_count', c_uint16),       # Number of elements to write
        ('data', c_uint8 * 256),           # Buffer for tag data
    ]
    def __init__(self, data=None):
        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))

class UnconnectedSendData(Structure):
    """CIP: Unconnected Send (0x52)"""
    _pack_ = 1
    _fields_ = [
        ('service', c_uint8),              # Encapsulated service
        ('timeout', c_uint8),              # Timeout for the unconnected message
        ('message_length', c_uint16),      # Length of the encapsulated message
        ('message', c_uint8 * 256),        # Encapsulated CIP message
    ]
    def __init__(self, data=None):
        if data:
            memmove(addressof(self), data[:sizeof(self)], sizeof(self))

