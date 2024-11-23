from ctypes import *
import logging
import struct

class NullAddressItem(Structure):
    """CIP: Type ID: 0x0000"""
    _pack_ = 1
    _fields_ = [
        ('type_id', c_uint16),             # 0x00 for Null Address
        ('length', c_uint16),              # length of data for the item
        ('data', c_uint8 * 0)              # Placeholder for dynamic data (Always 0 bytes)
    ]

    def __init__(self):
        self.type_id = 0x0000
        self.length = 0

    def to_bytes(self):
        return bytes(self)


class UnconnectedDataItem(Structure):
    """
    Represents the Unconnected Data Item in CIP.
    The length of `data` is determined dynamically based on item1_len.
    """
    _pack_ = 1
    _fields_ = [
        ('type_id', c_uint16),  # Type ID (0x00B2 for Unconnected Data Item)
        ('length', c_uint16),  # Length of the data (dynamic)
    ]

    def __init__(self, data_bytes):
        """
        Initialize the Unconnected Data Item.
        :param data_bytes: The CIP payload (as bytes).
        """
        self.type_id = 0x00B2  # Fixed type for Unconnected Data Item
        self.length = len(data_bytes)
        # Dynamically set the `data` field to the size of the payload
        self.data = (c_uint8 * self.length).from_buffer_copy(data_bytes)

    def to_bytes(self):
        """Convert the Unconnected Data Item to bytes."""
        return bytes(self) + bytes(self.data)


class SocketAddressInfo(Structure):
    _pack_ = 1
    _fields_ = [
        ('type_id', c_uint16),  # Type ID (0x8000 for SocketAddressInfo)
        ('length', c_uint16),  # Length of the data
        ('sin_family', c_uint16),
        ('sin_port', c_uint16),
        ('sin_addr', c_uint32),
        ('sin_zero', c_uint8 * 8)
    ]

    def __init__(self, socket_info):
        """Socket info passed from the EIP_Adapter."""
        self.sin_family = socket_info['family']
        self.sin_port = socket_info['port']
        self.sin_addr = socket_info['address']
        self.type_id = 0x8000
        self.length = len(self.to_bytes()) - 4

    def to_bytes(self):
        """Convert to bytes."""
        return bytes(self)