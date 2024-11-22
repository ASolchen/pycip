from ctypes import *
import logging

class ForwardOpenRequest(Structure):
    """CIP Forward Open Request structure based on CIP Table 3-5.16."""
    _pack_ = 1
    _fields_ = [
        ('tick_time', c_uint8, 4),       # Timeout Ticks (4 bits)
        ('priority', c_uint8, 1),            # Priority (1 bit)
        ('reserved_01', c_uint8, 3),         # Reserved (3 bits)
        ('time-out_ticks', c_uint8),    # O->T Connection ID
        ('o_t_connection_id', c_uint32),    # O->T Connection ID
        ('t_o_connection_id', c_uint32),    # T->O Connection ID
        ('connection_serial_number', c_uint16),  # Connection Serial Number
        ('vendor_id', c_uint16),            # Vendor ID
        ('originator_serial_number', c_uint32),  # Originator Serial Number
        ('connection_to_multiplier', c_uint8),   # Connection Timeout Multiplier
        ('reserved_02', c_uint8 * 3),       # Reserved
        ('o_t_rpi', c_uint32),              # O->T Requested Packet Interval (RPI)
        ('o_t_network_params', c_uint16),   # O->T Network Parameters
        ('t_o_rpi', c_uint32),              # T->O Requested Packet Interval (RPI)
        ('t_o_network_params', c_uint16),   # T->O Network Parameters
        ('transport_type', c_uint8),        # Transport Type/Trigger
        ('connection_path_size', c_uint8),  # Connection Path Size (in words)
        ('connection_path', c_uint8 * 40),  # Encoded Path (variable length, max 40 bytes)
    ]



#TODO fix response

class ForwardOpenResponse(Structure):
    _pack_ = 1
    _fields_ = [
        ('service', c_uint8),               # CIP Service Code (response bit set)
        ('status', c_uint8),                # General Status
        ('additional_status_size', c_uint8),# Size of Additional Status in words
        ('reserved', c_uint8),              # Reserved
        ('o_t_connection_id', c_uint32),    # O->T Connection ID
        ('t_o_connection_id', c_uint32),    # T->O Connection ID
        ('o_t_rpi', c_uint32),              # O->T RPI
        ('t_o_rpi', c_uint32),              # T->O RPI
        ('o_t_network_params', c_uint16),   # O->T Network Parameters
        ('t_o_network_params', c_uint16),   # T->O Network Parameters
        ('reserved_padding', c_uint8 * 8),  # Reserved for alignment
    ]


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

class GetAttributeSingleData(Structure):
    _pack_ = 1
    _fields_ = [
        ('class_id', c_uint8),             # Object Class
        ('instance_id', c_uint8),          # Object Instance
        ('attribute_id', c_uint8),         # Attribute ID
    ]

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

class ResetData(Structure):
    """CIP: Reset (0x05)"""
    _pack_ = 1
    _fields_ = [
        ('reset_type', c_uint8),           # Reset Type (0x00 = Soft Reset, 0x01 = Hard Reset)
    ]

class ReadTagServiceData(Structure):
    """CIP: Read Tag Service (0x4C)"""
    _pack_ = 1
    _fields_ = [
        ('tag_name_length', c_uint16),     # Length of the tag name
        ('tag_name', c_char * 64),         # Tag name (null-terminated string)
        ('offset', c_uint32),              # Offset (used for arrays)
        ('element_count', c_uint16),       # Number of elements to read
    ]

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

class UnconnectedSendData(Structure):
    """CIP: Unconnected Send (0x52)"""
    _pack_ = 1
    _fields_ = [
        ('service', c_uint8),              # Encapsulated service
        ('timeout', c_uint8),              # Timeout for the unconnected message
        ('message_length', c_uint16),      # Length of the encapsulated message
        ('message', c_uint8 * 256),        # Encapsulated CIP message
    ]

